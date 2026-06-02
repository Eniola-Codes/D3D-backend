import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';

const r2 = new S3Client({
    region: 'auto',
    endpoint: process.env.R2_ENDPOINT ?? '',
    credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY_ID ?? '',
        secretAccessKey: process.env.R2_SECRET_ACCESS_KEY ?? '',
    },
});

const createPutObjectCommand = (featuredImage: Buffer, key: string) => {
    return new PutObjectCommand({
        Bucket: process.env.R2_BUCKET_NAME,
        Key: key,
        Body: featuredImage,
    });
}

export { r2, createPutObjectCommand };
