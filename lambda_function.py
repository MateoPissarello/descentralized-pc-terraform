import boto3
import os
import tempfile
import json

s3 = boto3.client('s3')
sqs = boto3.client('sqs')

def lambda_handler(event, context):
    bucket = event['Records'][0]['s3']['bucket']['name']
    key    = event['Records'][0]['s3']['object']['key']
    output_bucket = os.environ['OUTPUT_BUCKET']
    queue_url = os.environ['SQS_QUEUE_URL']

    with tempfile.TemporaryDirectory() as tmpdir:
        local_path = os.path.join(tmpdir, "original")
        s3.download_file(bucket, key, local_path)

        with open(local_path, "rb") as f:
            content = f.read()
            size = len(content)
            part_size = size // 3

            for i in range(3):
                part = content[i*part_size : (i+1)*part_size] if i < 2 else content[i*part_size:]
                part_key = f"{key}_part_{i+1}"
                s3.put_object(Bucket=output_bucket, Key=part_key, Body=part)

                # Enviar mensaje a SQS
                sqs.send_message(
                    QueueUrl=queue_url,
                    MessageBody=json.dumps({
                        "bucket": output_bucket,
                        "part_key": part_key,
                        "original_file": key,
                        "part_number": i + 1,
                    })
                )


            

    return {"status": "success"}
