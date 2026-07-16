import string
import secrets
import math
import re

# [RULE-01] and [RULE-02] Dictionary of weak passwords / basic dictionary
# For practical purposes, we simulate a list of the weakest passwords
TOP_PEORES = {
    "123456", "password", "12345678", "qwerty", "12345", "123456789", 
    "iloveyou", "admin", "111111", "contraseña", "contrasenia", "qazwsx",
    "password123", "admin123", "welcome", "sunshine", "monkey"
}

def cargar_diccionario_prohibido():
    return TOP_PEORES

def calcular_entropia(contrasena, tamaño_pool):
    """Calculates theoretical entropy bits: E = L * log2(R)"""
    longitud = len(contrasena)
    if longitud == 0:
        return 0
    bits_entropia = longitud * math.log2(tamaño_pool)
    return round(bits_entropia, 2)

def generar_super_password(longitud=18, permitir_espacios=True, contrasena_antigua=None, datos_entorno=None):
    """
    Generates a cryptographically secure password based on corporate and NIST guidelines.
    """
    # [RULE-05] and [RULE-06] Minimum and maximum NIST length
    if longitud < 12 or longitud > 64:
        raise ValueError("Length must be between 12 and 64 characters (NIST / Corporate Standard).")

    if datos_entorno is None:
        datos_entorno = []
    
    # Add old password to environment data if provided
    if contrasena_antigua:
        datos_entorno.append(contrasena_antigua)
        # Extract alphanumeric words from the old password to block them as well
        partes_antigua = re.split(r'[^a-zA-Z0-9]', contrasena_antigua)
        datos_entorno.extend([p for p in partes_antigua if len(p) >= 4])

    # Pre-process environment data for case-insensitive search
    datos_entorno_lower = [str(dato).lower() for dato in datos_entorno if len(str(dato)) >= 3]
    diccionario_prohibido = cargar_diccionario_prohibido()

    # [RULE-07] Character pools including all printable ASCII characters
    # [RULE-12] Exclusion of homoglyphs (l, 1, I, o, 0, O)
    minusculas = set(string.ascii_lowercase) - set('lo')
    mayusculas = set(string.ascii_uppercase) - set('IO')
    numeros = set(string.digits) - set('01')
    simbolos_todos = set(string.punctuation)
    espacio = set(" ") if permitir_espacios else set()

    universo_set = minusculas | mayusculas | numeros | simbolos_todos | espacio
    universo = list(universo_set)
    tamaño_pool = len(universo)

    # [RULE-03] Mandatory institutional characters
    simbolos_institucionales = set("!@#$%^&*()")

    while True:
        # [RULE-11] Use CSPRNG for real entropy
        contrasena = ''.join(secrets.choice(universo) for _ in range(longitud))

        # [RULE-15] Avoid spaces at the edges to prevent trimming issues
        if contrasena.startswith(' ') or contrasena.endswith(' '):
            continue

        # [RULE-03] Validation of mandatory groups
        tiene_min = any(c in minusculas for c in contrasena)
        tiene_may = any(c in mayusculas for c in contrasena)
        tiene_num = any(c in numeros for c in contrasena)
        tiene_sym_inst = any(c in simbolos_institucionales for c in contrasena)

        if not (tiene_min and tiene_may and tiene_num and tiene_sym_inst):
            continue

        # [RULE-14] Avoid three consecutive identical characters (e.g. "aaa")
        repetitivo = any(contrasena[i] == contrasena[i+1] == contrasena[i+2] for i in range(len(contrasena)-2))
        if repetitivo:
            continue

        # [RULE-13] Avoid sequential scale patterns (ascending and descending)
        secuencial = False
        for i in range(len(contrasena) - 2):
            o1, o2, o3 = ord(contrasena[i]), ord(contrasena[i+1]), ord(contrasena[i+2])
            if (o2 == o1 + 1 and o3 == o2 + 1) or (o2 == o1 - 1 and o3 == o2 - 1):
                secuencial = True
                break
        if secuencial:
            continue

        # [RULE-01 and RULE-02] Dictionary filter
        contrasena_lower = contrasena.lower()
        if any(palabra in contrasena_lower for palabra in diccionario_prohibido if len(palabra) >= 4):
            continue
        
        # [RULE-04] Evaluate environment data in the generated password
        if any(dato in contrasena_lower for dato in datos_entorno_lower):
            continue

        entropia = calcular_entropia(contrasena, tamaño_pool)

        # [RULE-16] Return if entropy is sufficient
        if entropia >= 80:
            return contrasena, entropia