import boto3
import os
from botocore.exceptions import ClientError

# Config
REGION = "us-east-1"
KMS_KEY_ID = os.environ["KMS_KEY_ID"]
EFS_MOUNT_PATH = "/mnt/encryption"
DELIMITER = b"\x00\xffDELIM\xff\x00"  # Delimitador especial

# Inicializar cliente KMS
kms = boto3.client("kms", region_name=REGION)


def decrypt_local_file(encrypted_filename):
    encrypted_file_path = os.path.join(EFS_MOUNT_PATH, encrypted_filename)

    # Leer archivo cifrado
    print(f"[INFO] Leyendo archivo cifrado: {encrypted_filename}")
    with open(encrypted_file_path, "rb") as f:
        encrypted_data = f.read()

    # Separar las partes cifradas usando el delimitador
    parts = encrypted_data.split(DELIMITER)

    decrypted_data = b""

    # Desencriptar cada parte
    for i, part in enumerate(parts):
        try:
            print(f"[INFO] Desencriptando parte {i + 1}...")
            response = kms.decrypt(CiphertextBlob=part)
            decrypted_data += response["Plaintext"]
        except ClientError as e:
            print(f"[ERROR] Falló la desencriptación de la parte {i + 1}: {e}")
            return

    # Obtener nombre del archivo original eliminando ".final.enc"
    if encrypted_filename.endswith(".final.enc"):
        output_filename = encrypted_filename[: -len(".final.enc")]
    else:
        output_filename = encrypted_filename + ".decrypted"  # Fallback

    output_path = os.path.join(EFS_MOUNT_PATH, output_filename)
    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    print(f"[INFO] Archivo desencriptado guardado como: {output_filename}")


if __name__ == "__main__":
    encrypted_filename = input("Ingresa el nombre del archivo cifrado (.final.enc): ")
    decrypt_local_file(encrypted_filename)
