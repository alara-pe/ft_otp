import argparse
import hashlib
import hmac
import struct
import time
import base64
import qrcode



import pyotp


# Registra la clave inicial en hexadecimal
clave_inicial_hex = '19a2cfe15c4011f25c5a0e5f5a5c5a34e11d296b20f974cc202a0c283a88a0f1'

# Convierte la clave hex a base32 usando base64
clave_inicial_base32 = base64.b32encode(bytes.fromhex(clave_inicial_hex)).decode('utf-8')

# Crea una instancia de TOTP con la clave base32
totp = pyotp.TOTP(clave_inicial_base32)




def guardar_clave(archivo_b32, clave_hex):
    if not len(clave_hex) == 64 or not all(c in "0123456789abcdef" for c in clave_hex):
        raise ValueError("La clave debe tener 64 caracteres hexadecimales")

    # encode key in Base32 format
    clave_b32 = base64.b32encode(bytes.fromhex(clave_hex)).decode()

    # guardar clave en archivo
    with open(archivo_b32, "w") as f:
        f.write(clave_b32)


import base64

def generar_contrasena(archivo_key):
    with open(archivo_key, "r") as f:
        clave_b32 = f.read().strip()

    # decode key from Base32 format to bytes
    clave_bytes = base64.b32decode(clave_b32)

    tiempo = int(time.time())
    tiempo_int = tiempo // 30
    tiempo_bytes = struct.pack(">q", tiempo_int)

    hmac_obj = hmac.new(clave_bytes, tiempo_bytes, hashlib.sha1)
    hmac_digest = hmac_obj.digest()

    offset = hmac_digest[-1] & 0x0F
    codigo = (struct.unpack(">I", hmac_digest[offset:offset+4])[0] & 0x7FFFFFFF) % 10**6
    contrasena = str(codigo).zfill(6)

    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(contrasena)
    qr.make(fit=True)

    # display QR code
    qr.print_ascii()

    return contrasena

def main():
    parser = argparse.ArgumentParser(description="Generador de contraseñas temporales")
    parser.add_argument("-g", "--generar", help="Generar y guardar una clave secreta a partir de un archivo hexadecimal", type=str)
    parser.add_argument("-k", "--contrasena", help="Generar una nueva contraseña temporal cada 30 segundos", action="store_true")
    parser.add_argument("archivo_key", help="Archivo de clave secreta", nargs="?")

    args = parser.parse_args()

    if args.generar:
        guardar_clave("ft_otp.key", args.generar)
        print("La clave se guardó correctamente en ft_otp.key")

    if args.contrasena:
        if args.archivo_key:
            while True:
                contrasena_temporal = totp.now()
                contrasena = generar_contrasena(args.archivo_key)
                print("Contraseña temporal:", contrasena, "pyotp: ",contrasena_temporal)
                time.sleep(30)
        else:
            print("Error: Debes proporcionar el nombre del archivo de clave secreta")


if __name__ == "__main__":
    main()
