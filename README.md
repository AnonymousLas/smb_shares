# 🧰 SMB Loot Plus

`SMB Loot Plus` es un script avanzado en Python para enumerar y saquear recursos compartidos SMB durante auditorías o CTFs. No solo lista y descarga archivos accesibles, sino que también muestra la estructura de directorios con sus respectivos permisos, indica visualmente las descargas en progreso y analiza los archivos en busca de posibles credenciales.

---

## 🚀 Características

- ✅ Conexión automática a SMB con o sin autenticación  
- ✅ Muestra todos los *shares* y sus permisos (lectura o acceso denegado)  
- ✅ Visualización tipo árbol 📂 de directorios accesibles  
- ✅ Descarga recursiva 📥 de archivos desde carpetas accesibles  
- ✅ Detección de posibles credenciales en los archivos descargados 🔐  
- ✅ Colores y símbolos para facilitar la lectura (gracias a `colorama`)  
- ✅ Soporte para credenciales de Active Directory

---

## 🖥️ Requisitos

```bash
pip install impacket colorama
```
🛠 Uso
```bash
PROTO   IP              PORT  DOMAIN      SHARE                 PERM          REMARK
------------------------------------------------------------------------------------------
SMB      10.10.11.222    445   AUTHORITY   ADMIN$                -             -
SMB      10.10.11.222    445   AUTHORITY   C$                    -             -
SMB      10.10.11.222    445   AUTHORITY   Department Shares     ACCESS DENIED -
SMB      10.10.11.222    445   AUTHORITY   Development           READ          -
SMB      10.10.11.222    445   AUTHORITY   IPC$                  READ          -
SMB      10.10.11.222    445   AUTHORITY   NETLOGON              ACCESS DENIED -
SMB      10.10.11.222    445   AUTHORITY   SYSVOL                ACCESS DENIED -
```
Con acceso anónimo o guest
```bash
python smb_loot_plus.py 10.10.11.222 -u guest -p ""
```
Con autenticación
```bash
python smb_loot_plus.py 10.10.11.222 -u juan.perez -p "Password123" -d DOMINIO
```
Opcional: cambiar carpeta de descarga
```bash
python smb_loot_plus.py 10.10.11.222 -o salida_smb
```
🧪 ¿Qué muestra?
Árbol de carpetas accesibles:

```bash
[*] Share encontrado: Development
[R] Automation/
    [R] Ansible/
        [R] LDAP/
        [X] Vault/
```
Descarga con íconos:

```bash
📥 Descargando: Development/Automation/Ansible/LDAP/tasks/main.yml
Detección de posibles credenciales:

```
🔐 Posible credencial en main.yml: password = admin123
📂 Estructura de salida
Los archivos descargados se guardan en:
```bash
loot/
└── 10.10.11.222/
    └── Development/
        └── Automation/
            └── Ansible/
                └── LDAP/
```       
📌 Notas
El script infiere permisos de lectura al intentar listar carpetas (si falla, muestra [X]).

No intenta escribir por defecto para evitar alertas. Puedes extenderlo para verificar permisos de escritura si lo deseas.

⚠️ Advertencia
Este script es para uso educativo o de auditoría autorizada. No lo uses contra sistemas sin permiso. Tú eres responsable del uso que le des.
