
# 🧠 PC Descentralizado para Encriptación de Archivos en AWS

Este proyecto implementa un sistema de encriptación descentralizado en la nube utilizando servicios de AWS como S3, Lambda, SQS, EC2, DynamoDB, EFS y KMS. El objetivo es simular el comportamiento de un “PC descentralizado” que divide, encripta y almacena archivos en la nube de forma distribuida y segura.

---

## 📘 Introducción

La arquitectura permite cargar archivos a un bucket de S3, los cuales son automáticamente divididos en partes mediante una función Lambda. Estas partes son enviadas a una cola SQS, de donde varias instancias EC2, desplegadas en zonas de disponibilidad distintas, las consumen para encriptarlas. Las partes encriptadas son almacenadas nuevamente en S3, y una vez que todas han sido procesadas, pueden ser reunificadas y desencriptadas manualmente desde cualquier nodo.

---

## 📋 Requisitos

Antes de desplegar la arquitectura, asegúrate de contar con:

- ✅ Una cuenta activa de AWS.
- ✅ Terraform >= 1.2.0 instalado.
- ✅ AWS CLI configurado (`aws configure`).
- ✅ Una clave SSH existente en EC2 llamada `decentralized_pc`.
- ✅ Archivo `lambda_function.zip` en el mismo directorio del proyecto.
- ✅ Script `encryption_user_data.sh` en el directorio del proyecto.
- ✅ Clave KMS ya creada en la región `us-east-1`, con su ARN disponible.

### 🔁 Modificación obligatoria

Abre el archivo `main.tf` y reemplaza el valor por defecto de la variable `kms_key_arn` con **el ARN de tu propia clave KMS**:

```hcl
variable "kms_key_arn" {
  type        = string
  description = "ARN de la clave KMS utilizada para cifrar/descifrar"
  default     = "arn:aws:kms:us-east-1:<tu-cuenta-id>:key/<tu-key-id>"
}
```

---

## 🚀 Getting Started

### 1. Clona este repositorio
```bash
git clone https://github.com/MateoPissarello/descentralized-pc-terraform.git
cd descentralized-pc-terraform
```

### 2. Inicializa Terraform
```bash
terraform init
```

### 3. Aplica la infraestructura
```bash
terraform apply
```

> Esto desplegará buckets S3, Lambda, SQS, VPC, subredes, instancias EC2, EFS, DynamoDB, roles e IAM necesarios.

---

## 🛠️ Guía de uso

### 🔐 Encriptar un archivo

1. **Sube un archivo al bucket `decentralized-file-input` de S3.**
   Esto puede hacerse por consola o con `aws cli`:
   ```bash
   aws s3 cp archivo.txt s3://decentralized-file-input/
   ```

2. **La función Lambda será activada automáticamente**, dividirá el archivo en 3 partes y las enviará al bucket `decentralized-encryption-parts`, además de notificar a través de SQS.

3. **Las instancias EC2 (Encryptor-Node-1, 2 y 3)** consumirán los mensajes desde la cola SQS, encriptarán cada parte usando AWS KMS y las subirán al bucket `decentralized-encrypted-parts-output`.

4. **Una vez las tres partes estén listas**, cualquier de las instancias EC2 asume el rol de unificador y el archivo es guardado en `decentralized-encrypted-output`.

---

### 🔓 Desencriptar un archivo

1. **Conéctate por SSH a cualquiera de las instancias EC2:**
   ```bash
   ssh -i decentralized_pc.pem ec2-user@<IP_PUBLICA_EC2>
   ```

2. **Asegúrate de que el archivo cifrado final (`.final.enc`) esté presente en el sistema de archivos compartido (EFS).**  
   Este archivo debe haber sido creado previamente por el proceso de encriptación.

3. **Ejecuta el script `decrypt_local_file.py` ubicado en el EFS** e ingresa el nombre del archivo cifrado cuando se te solicite:
   ```bash
   python3 decrypt_local_file.py
   ```

4. **El script solicitará el nombre del archivo cifrado (por ejemplo, `archivo.txt.final.enc`).**
   Luego desencriptará las partes usando KMS y generará el archivo original restaurado en el mismo directorio del EFS.

   Verás un mensaje similar a este:
   ```
   [INFO] Leyendo archivo cifrado: archivo.txt.final.enc
   [INFO] Desencriptando parte 1...
   [INFO] Desencriptando parte 2...
   [INFO] Desencriptando parte 3...
   [INFO] Archivo desencriptado guardado como: archivo.txt
   ```

---

## 🧱 Arquitectura

![Arquitectura Descentralizada](./img/Arquitectura%20complejos.png)

### Componentes:

- **S3 Buckets:** Entrada, partes, partes encriptadas, y salida final.
- **Lambda (split-lambda):** Divide archivos al cargarse en S3.
- **SQS:** Cola para coordinar el procesamiento paralelo.
- **EC2 en AZs diferentes:** Cada nodo procesa una parte.
- **DynamoDB:** Coordina el estado de encriptación por parte.
- **EFS:** Almacenamiento compartido entre nodos.
- **KMS:** Gestión de claves de encriptación/descifrado.
