//! Cloudflare R2 (S3-compatible) object storage client.

use std::time::Duration;

use aws_config::Region;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::config::Credentials;
use aws_sdk_s3::presigning::PresigningConfig;
use uuid::Uuid;

use crate::config::R2Config;
use crate::core::error::AppError;

pub struct R2Client {
    client: S3Client,
    bucket: String,
    presign_ttl: Duration,
}

impl R2Client {
    pub async fn new(config: &R2Config) -> Result<Self, anyhow::Error> {
        let creds = Credentials::new(
            &config.access_key_id,
            &config.secret_access_key,
            None,
            None,
            "r2-static-creds",
        );

        let config_builder = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .credentials_provider(creds)
            .region(Region::new("auto"));

        let aws_config = if !config.endpoint.is_empty() {
            config_builder.endpoint_url(&config.endpoint).load().await
        } else {
            config_builder.load().await
        };

        let s3_config = aws_sdk_s3::Config::from(&aws_config)
            .to_builder()
            .force_path_style(true)
            .build();

        let client = S3Client::from_conf(s3_config);

        Ok(Self {
            client,
            bucket: config.bucket.clone(),
            presign_ttl: Duration::from_secs(config.presign_ttl_seconds),
        })
    }

    /// R2 key layout: `{user_id}/{file_id}/{version_id}/{segment_index}/{chunk_index}`
    /// Flat, never encodes filename or folder name.
    pub fn chunk_key(
        user_id: Uuid,
        file_id: Uuid,
        version_id: Uuid,
        segment_index: i32,
        chunk_index: i32,
    ) -> String {
        format!(
            "{}/{}/{}/{}/{}",
            user_id, file_id, version_id, segment_index, chunk_index
        )
    }

    pub async fn presign_put(&self, key: &str) -> Result<String, AppError> {
        let presign_config = PresigningConfig::expires_in(self.presign_ttl).map_err(|e| {
            tracing::error!(error = ?e, "failed to create presign config");
            AppError::Internal(anyhow::anyhow!("storage configuration error"))
        })?;

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .presigned(presign_config)
            .await
            .map(|p| p.uri().to_string())
            .map_err(|e| {
                tracing::error!(error = ?e, key, "failed to presign PUT");
                AppError::ServiceUnavailable("failed to generate upload URL".to_string())
            })
    }

    pub async fn presign_get(&self, key: &str) -> Result<String, AppError> {
        let presign_config = PresigningConfig::expires_in(self.presign_ttl).map_err(|e| {
            tracing::error!(error = ?e, "failed to create presign config");
            AppError::Internal(anyhow::anyhow!("storage configuration error"))
        })?;

        self.client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .presigned(presign_config)
            .await
            .map(|p| p.uri().to_string())
            .map_err(|e| {
                tracing::error!(error = ?e, key, "failed to presign GET");
                AppError::ServiceUnavailable("failed to generate download URL".to_string())
            })
    }

    /// HEAD object — returns ETag if object exists, None if not found.
    pub async fn head_object(&self, key: &str) -> Result<Option<String>, AppError> {
        let resp = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await;

        match resp {
            Ok(head) => Ok(head.e_tag),
            Err(aws_sdk_s3::error::SdkError::ServiceError(err)) => {
                let status = err.raw().status().as_u16();

                if status == 404 {
                    Ok(None)
                } else {
                    tracing::error!(error = ?err, key, status, "R2 HEAD failed");
                    if status == 403 {
                        Err(AppError::Internal(anyhow::anyhow!("storage access denied")))
                    } else {
                        Err(AppError::ServiceUnavailable(
                            "storage temporarily unavailable".into(),
                        ))
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = ?e, key, "R2 HEAD failed (transient or network)");
                Err(AppError::ServiceUnavailable(
                    "storage temporarily unavailable".into(),
                ))
            }
        }
    }

    pub async fn delete_object(&self, key: &str) -> Result<(), AppError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map(|_| ())
            .map_err(|e| {
                tracing::error!(error = ?e, key, "R2 DELETE failed");
                AppError::Internal(anyhow::anyhow!("storage deletion failed"))
            })
    }

    /// Batch delete up to 1000 objects in a single request.
    pub async fn delete_objects(&self, keys: &[String]) -> Result<(), AppError> {
        if keys.is_empty() {
            return Ok(());
        }

        let objects: Vec<_> = keys
            .iter()
            .map(|k| {
                aws_sdk_s3::types::ObjectIdentifier::builder()
                    .key(k)
                    .build()
            })
            .collect::<Result<_, _>>()
            .map_err(|e| {
                tracing::error!(error = ?e, "failed to build delete batch");
                AppError::Internal(anyhow::anyhow!("batch delete build failed"))
            })?;

        self.client
            .delete_objects()
            .bucket(&self.bucket)
            .delete(
                aws_sdk_s3::types::Delete::builder()
                    .set_objects(Some(objects))
                    .quiet(true)
                    .build()
                    .map_err(|e| {
                        tracing::error!(error = ?e, "failed to build Delete request");
                        AppError::Internal(anyhow::anyhow!("batch delete build failed"))
                    })?,
            )
            .send()
            .await
            .map(|_| ())
            .map_err(|e| {
                tracing::error!(error = ?e, "R2 batch DELETE failed");
                AppError::Internal(anyhow::anyhow!("batch delete failed"))
            })
    }

    pub async fn upload_object(&self, key: &str, data: Vec<u8>) -> Result<(), AppError> {
        use aws_sdk_s3::primitives::ByteStream;

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(data))
            .send()
            .await
            .map(|_| ())
            .map_err(|e| {
                tracing::error!(error = ?e, key, "R2 PUT failed");
                AppError::ServiceUnavailable("storage upload failed".to_string())
            })
    }

    pub async fn presign_get_with_filename(
        &self,
        key: &str,
        filename: &str,
    ) -> Result<String, AppError> {
        let presign_config = PresigningConfig::expires_in(self.presign_ttl)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("storage configuration error")))?;

        let safe_filename = filename.replace('"', "").replace('\n', "");
        let content_disposition = format!("attachment; filename=\"{}\"", safe_filename);

        self.client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .response_content_disposition(content_disposition)
            .presigned(presign_config)
            .await
            .map(|p| p.uri().to_string())
            .map_err(|e| {
                tracing::error!(error = ?e, key, "failed to presign GET");
                AppError::ServiceUnavailable("failed to generate download URL".to_string())
            })
    }
}
