#!/bin/bash
# Actualizar el sistema e instalar dependencias
yum update -y
yum install -y amazon-efs-utils nfs-utils python3 python3-pip git

systemctl enable crond
systemctl start crond

# Configurar variables de entorno
cat << 'EOF' > /etc/profile.d/encryption_env.sh
export SQS_QUEUE_URL="${SQS_QUEUE_URL}"
export INPUT_BUCKET="${INPUT_BUCKET}"
export PARTS_BUCKET="${PARTS_BUCKET}"
export ENCRYPTED_PARTS_BUCKET="${ENCRYPTED_PARTS_BUCKET}"
export ENCRYPTED_OUTPUT_BUCKET="${ENCRYPTED_OUTPUT_BUCKET}"
export KMS_KEY_ID="${KMS_KEY_ID}" 
export DYNAMO_TABLE="${DYNAMO_TABLE}"
export PYTHONUNBUFFERED=1
EOF
chmod +x /etc/profile.d/encryption_env.sh

# Asegurarse de que las variables de entorno estén disponibles para todos los scripts
source /etc/profile.d/encryption_env.sh

# Instalar dependencias de Python
pip3 install boto3

# Crear directorio para el montaje de EFS
mkdir -p /mnt/encryption

# Montar EFS con reintento
echo "$(date): Intentando montar EFS..." >> /var/log/efs_mount.log
for i in {1..30}; do
  if mount -t efs -o tls ${EFS_ID}:/ /mnt/encryption; then
    echo "$(date): EFS montado correctamente" >> /var/log/efs_mount.log
    break
  else
    echo "$(date): Intento $i: EFS aún no disponible, esperando 10 segundos..." >> /var/log/efs_mount.log
    sleep 10
  fi
done

# Verificar y registrar en fstab para persistencia
if mountpoint -q /mnt/encryption; then
  echo "$(date): Verificación: EFS está correctamente montado" >> /var/log/efs_mount.log
  grep -q "${EFS_ID}" /etc/fstab || echo "${EFS_ID}:/ /mnt/encryption efs _netdev,tls,iam 0 0" >> /etc/fstab
else
  echo "$(date): ERROR: No se pudo montar EFS después de varios intentos" >> /var/log/efs_mount.log
  exit 1  # Salir con error si no se puede montar EFS
fi

# Cambiar permisos del punto de montaje
chown ec2-user:ec2-user /mnt/encryption
chmod 755 /mnt/encryption

# Escribir el worker en el EFS
cat > /mnt/encryption/encrypt_worker.py << 'EOF'
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
EOF

# Asegurarse de que el script tiene permisos de ejecución
chmod +x /mnt/encryption/encrypt_worker.py

# Crear un archivo de servicio de systemd para el worker
# CAMBIO CLAVE: Usar hereDOC sin comillas para permitir expansión de variables
cat << EOF > /etc/systemd/system/encrypt-worker.service
[Unit]
Description=Encryption Worker Service
After=network.target

[Service]
Type=simple
User=ec2-user
# CAMBIO CLAVE: Definir variables de entorno directamente en lugar de usar EnvironmentFile
Environment="SQS_QUEUE_URL=${SQS_QUEUE_URL}"
Environment="INPUT_BUCKET=${INPUT_BUCKET}"
Environment="PARTS_BUCKET=${PARTS_BUCKET}"
Environment="ENCRYPTED_PARTS_BUCKET=${ENCRYPTED_PARTS_BUCKET}"
Environment="ENCRYPTED_OUTPUT_BUCKET=${ENCRYPTED_OUTPUT_BUCKET}"
Environment="KMS_KEY_ID=${KMS_KEY_ID}"
Environment="DYNAMO_TABLE=${DYNAMO_TABLE}"
Environment="PYTHONUNBUFFERED=1"
ExecStart=/usr/bin/python3 /mnt/encryption/encrypt_worker.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Habilitar y iniciar el servicio
systemctl daemon-reload
systemctl enable encrypt-worker
systemctl start encrypt-worker

# Verificar que las variables de entorno se cargan correctamente
sleep 5
echo "Verificando variables de entorno del servicio:" > /var/log/service_vars.log
systemctl show -p Environment encrypt-worker >> /var/log/service_vars.log

# Script para verificar montaje de EFS
cat > /usr/local/bin/check_efs_mount.sh << 'CHECKSCRIPT'
#!/bin/bash
if ! mountpoint -q /mnt/encryption; then
  echo "$(date): EFS no está montado, intentando montar..." >> /var/log/efs_mount.log
  mount -t efs -o tls ${EFS_ID}:/ /mnt/encryption
  if [ $? -eq 0 ]; then
    echo "$(date): EFS montado correctamente" >> /var/log/efs_mount.log
    chown ec2-user:ec2-user /mnt/encryption
    chmod 755 /mnt/encryption
    # Reiniciar el servicio si el EFS se volvió a montar
    systemctl restart encrypt-worker
  else
    echo "$(date): Error al montar EFS" >> /var/log/efs_mount.log
  fi
fi

# Verificar que el servicio esté funcionando
if ! systemctl is-active --quiet encrypt-worker; then
  echo "$(date): El servicio encrypt-worker no está activo, intentando reiniciar..." >> /var/log/encrypt_worker.log
  systemctl restart encrypt-worker
fi
CHECKSCRIPT
chmod +x /usr/local/bin/check_efs_mount.sh

# Agregar tarea cron para verificar montaje y servicio cada 5 minutos
echo "*/5 * * * * root /usr/local/bin/check_efs_mount.sh" > /etc/cron.d/check-efs

# Verificar el estado del servicio
echo "$(date): Verificando estado del servicio encrypt-worker" >> /var/log/efs_mount.log
systemctl status encrypt-worker >> /var/log/efs_mount.log 2>&1

# Añadir script para verificar estado (opcional)
cat > /usr/local/bin/health_check.sh << 'HEALTHCHECK'
#!/bin/bash
# health_check.sh - Script para verificar el estado del worker

# Crear carpeta para reportes de estado si no existe
mkdir -p /var/log/status_reports

# Generar reporte
STATUS_FILE="/var/log/status_reports/status_$(date +%Y%m%d_%H%M%S).txt"

echo "== REPORTE DE ESTADO: $(date) ==" > $STATUS_FILE
echo "" >> $STATUS_FILE

# Verificar montaje EFS
echo "== ESTADO DEL MONTAJE EFS ==" >> $STATUS_FILE
if mountpoint -q /mnt/encryption; then
  echo "✅ EFS montado correctamente en /mnt/encryption" >> $STATUS_FILE
else
  echo "❌ EFS NO ESTÁ MONTADO!" >> $STATUS_FILE
fi
echo "" >> $STATUS_FILE

# Verificar servicio systemd
echo "== ESTADO DEL SERVICIO SYSTEMD ==" >> $STATUS_FILE
if systemctl is-active --quiet encrypt-worker; then
  echo "✅ Servicio encrypt-worker está ACTIVO" >> $STATUS_FILE
  systemctl status encrypt-worker --no-pager | tail -n 10 >> $STATUS_FILE
else
  echo "❌ Servicio encrypt-worker NO ESTÁ ACTIVO!" >> $STATUS_FILE
  systemctl status encrypt-worker --no-pager >> $STATUS_FILE
fi
echo "" >> $STATUS_FILE

# Verificar proceso Python
echo "== PROCESOS DE PYTHON RELACIONADOS ==" >> $STATUS_FILE
ps aux | grep "[e]ncrypt_worker.py" >> $STATUS_FILE
if [ $? -ne 0 ]; then
  echo "❌ No se encontró ningún proceso de encrypt_worker.py en ejecución!" >> $STATUS_FILE
fi
echo "" >> $STATUS_FILE

# Verificar logs recientes
echo "== ÚLTIMAS 10 LÍNEAS DE LOGS ==" >> $STATUS_FILE
echo "- encrypt_worker.log:" >> $STATUS_FILE
tail -n 10 /var/log/encrypt_worker.log >> $STATUS_FILE 2>&1
echo "" >> $STATUS_FILE
echo "- efs_mount.log:" >> $STATUS_FILE
tail -n 10 /var/log/efs_mount.log >> $STATUS_FILE 2>&1
echo "" >> $STATUS_FILE

# Verificar variables de entorno para el servicio
echo "== VARIABLES DE ENTORNO DEL SERVICIO ==" >> $STATUS_FILE
systemctl show -p Environment encrypt-worker >> $STATUS_FILE 2>&1
echo "" >> $STATUS_FILE

# Resumen de estado
echo "== RESUMEN DE ESTADO ==" >> $STATUS_FILE
if mountpoint -q /mnt/encryption && systemctl is-active --quiet encrypt-worker && ps aux | grep -q "[e]ncrypt_worker.py"; then
  echo "✅ TODO EN ORDEN: EFS montado, servicio activo y proceso en ejecución." >> $STATUS_FILE
else
  echo "❌ HAY PROBLEMAS: Revisar detalles arriba." >> $STATUS_FILE
fi

# Escribir estado actual al archivo latest para fácil acceso
cp $STATUS_FILE /var/log/status_reports/latest_status.txt

echo "Reporte guardado en: $STATUS_FILE"
HEALTHCHECK
chmod +x /usr/local/bin/health_check.sh

# Crear una tarea cron para ejecutar la verificación de estado cada hora
echo "0 * * * * root /usr/local/bin/health_check.sh > /dev/null 2>&1" > /etc/cron.d/health_check

# Ejecutar verificación de estado inicial
/usr/local/bin/health_check.sh