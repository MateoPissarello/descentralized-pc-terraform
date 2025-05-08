import boto3
import os
import time
import json
from botocore.exceptions import ClientError

# Config
REGION = "us-east-1"
QUEUE_URL = os.environ["SQS_QUEUE_URL"]
PARTS_BUCKET = os.environ["PARTS_BUCKET"]
ENCRYPTED_PARTS_BUCKET = os.environ["ENCRYPTED_PARTS_BUCKET"]
ENCRYPTED_OUTPUT_BUCKET = os.environ["ENCRYPTED_OUTPUT_BUCKET"]
KMS_KEY_ID = os.environ["KMS_KEY_ID"]
DYNAMO_TABLE = os.environ["DYNAMO_TABLE"]
EFS_MOUNT_PATH = "/mnt/encryption"

# Inicializar clientes
sqs = boto3.client("sqs", region_name=REGION)
s3 = boto3.client("s3", region_name=REGION)
kms = boto3.client("kms", region_name=REGION)
dynamodb = boto3.client("dynamodb", region_name=REGION)

def process_messages():
    while True:
        response = sqs.receive_message(QueueUrl=QUEUE_URL, MaxNumberOfMessages=1, WaitTimeSeconds=10)
        if "Messages" not in response:
            continue
        for msg in response["Messages"]:
            body = json.loads(msg["Body"])
            part_bucket = body.get("bucket", PARTS_BUCKET)  # Usa bucket del mensaje o el default
            part_key = body["part_key"]
            file_name = body["original_file"]
            part_number = body["part_number"]

            # Descargar la parte
            download_path = f"{EFS_MOUNT_PATH}/{part_key}"
            s3.download_file(part_bucket, part_key, download_path)

            # Leer y cifrar
            with open(download_path, "rb") as f:
                plaintext = f.read()

            encrypted = kms.encrypt(KeyId=KMS_KEY_ID, Plaintext=plaintext)["CiphertextBlob"]

            # Guardar local y subir a bucket de partes cifradas
            encrypted_filename = f"{file_name}.part{part_number}.enc"
            encrypted_path = f"{EFS_MOUNT_PATH}/{encrypted_filename}"
            with open(encrypted_path, "wb") as f:
                f.write(encrypted)

            s3.upload_file(encrypted_path, ENCRYPTED_PARTS_BUCKET, encrypted_filename)

            # Registrar en DynamoDB
            dynamodb.put_item(
                TableName=DYNAMO_TABLE,
                Item={
                    "original_file": {"S": file_name},
                    "part_number": {"N": str(part_number)},
                    "status": {"S": "ENCRYPTED"},
                    "timestamp": {"N": str(int(time.time()))},
                },
            )

            # Borrar mensaje de la cola
            sqs.delete_message(QueueUrl=QUEUE_URL, ReceiptHandle=msg["ReceiptHandle"])

            # Intentar unificar si corresponde
            try_unify(file_name)

def try_unify(file_name):
    response = dynamodb.query(
        TableName=DYNAMO_TABLE,
        KeyConditionExpression="original_file = :f",
        ExpressionAttributeValues={":f": {"S": file_name}},
    )
    parts = response["Items"]

    if len(parts) == 3 and all(p["status"]["S"] == "ENCRYPTED" for p in parts):
        try:
            dynamodb.update_item(
                TableName=DYNAMO_TABLE,
                Key={"original_file": {"S": file_name}, "part_number": {"N": "-1"}},
                UpdateExpression="SET #st = :s, #ts = :t",
                ExpressionAttributeNames={"#st": "status", "#ts": "timestamp"},
                ExpressionAttributeValues={":s": {"S": "UNIFYING"}, ":t": {"N": str(int(time.time()))}},
                ConditionExpression="attribute_not_exists(original_file) AND attribute_not_exists(part_number)",
            )
            unify_parts(file_name)
        except ClientError as e:
            if e.response['Error']['Code'] != 'ConditionalCheckFailedException':
                raise

def unify_parts(file_name):
    unified_path = f"{EFS_MOUNT_PATH}/{file_name}.final.enc"
    with open(unified_path, "wb") as outfile:
        for i in range(3):
            part_key = f"{file_name}.part{i + 1}.enc"
            part_path = f"{EFS_MOUNT_PATH}/{part_key}"
            s3.download_file(ENCRYPTED_PARTS_BUCKET, part_key, part_path)
            with open(part_path, "rb") as f:
                outfile.write(f.read())

    s3.upload_file(unified_path, ENCRYPTED_OUTPUT_BUCKET, f"{file_name}.final.enc")
    print(f"[UNIFIED] {file_name}.final.enc subido a {ENCRYPTED_OUTPUT_BUCKET}")

if __name__ == "__main__":
    process_messages()
