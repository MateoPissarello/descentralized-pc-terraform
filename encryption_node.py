import boto3
import os
import time
import json
from botocore.exceptions import ClientError

# Config
REGION = "us-east-1"
QUEUE_URL = os.environ["SQS_QUEUE_URL"]
INPUT_BUCKET = os.environ["INPUT_BUCKET"]
PARTS_BUCKET = os.environ["PARTS_BUCKET"]
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
            file_name = body["file_name"]
            part_number = body["part_number"]
            s3_key = body["s3_key"]

            # Descargar la parte
            download_path = f"{EFS_MOUNT_PATH}/{s3_key}"
            s3.download_file(PARTS_BUCKET, s3_key, download_path)

            # Leer y cifrar
            with open(download_path, "rb") as f:
                plaintext = f.read()

            encrypted = kms.encrypt(KeyId=KMS_KEY_ID, Plaintext=plaintext)["CiphertextBlob"]

            encrypted_path = f"{download_path}.enc"
            with open(encrypted_path, "wb") as f:
                f.write(encrypted)

            encrypted_key = f"{s3_key}.enc"
            s3.upload_file(encrypted_path, PARTS_BUCKET, encrypted_key)

            # Actualizar estado en DynamoDB
            dynamodb.put_item(
                TableName=DYNAMO_TABLE,
                Item={
                    "original_file": {"S": file_name},
                    "part_number": {"N": str(part_number)},
                    "status": {"S": "ENCRYPTED"},
                    "timestamp": {"N": str(int(time.time()))},
                },
            )

            # Borrar mensaje
            sqs.delete_message(QueueUrl=QUEUE_URL, ReceiptHandle=msg["ReceiptHandle"])

            # Intentar actuar como unificador
            try_unify(file_name)


def try_unify(file_name):
    # Consultar todas las partes
    response = dynamodb.query(
        TableName=DYNAMO_TABLE,
        KeyConditionExpression="original_file = :f",
        ExpressionAttributeValues={":f": {"S": file_name}},
    )
    parts = response["Items"]

    if len(parts) == 3 and all(p["status"]["S"] == "ENCRYPTED" for p in parts):
        try:
            # Intentar poner bandera de unificación de forma atómica
            dynamodb.update_item(
                TableName=DYNAMO_TABLE,
                Key={
                    "original_file": {"S": file_name},
                    "part_number": {"N": "-1"}
                },
                UpdateExpression="SET #st = :s, #ts = :t",
                ExpressionAttributeNames={
                    "#st": "status",
                    "#ts": "timestamp"
                },
                ExpressionAttributeValues={
                    ":s": {"S": "UNIFYING"},
                    ":t": {"N": str(int(time.time()))}
                },
                ConditionExpression="attribute_not_exists(original_file) AND attribute_not_exists(part_number)",
            )
            # Este nodo es el unificador
            unify_parts(file_name, parts)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                # Otro nodo ya se encargó
                pass
            else:
                raise


def unify_parts(file_name, parts):
    # Unir los .enc en orden
    with open(f"{EFS_MOUNT_PATH}/{file_name}.final.enc", "wb") as outfile:
        for i in range(3):
            key = f"{file_name}.part{i}.enc"
            path = f"{EFS_MOUNT_PATH}/{key}"
            s3.download_file(PARTS_BUCKET, key, path)
            with open(path, "rb") as f:
                outfile.write(f.read())
    print(f"[UNIFIED] {file_name}.final.enc listo.")


if __name__ == "__main__":
    process_messages()
