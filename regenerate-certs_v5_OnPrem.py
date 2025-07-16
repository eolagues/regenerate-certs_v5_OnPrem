#!/usr/bin/env python3

import ssl
from datetime import datetime, timezone
import OpenSSL.crypto as crypto
import subprocess
import os
import logging
import re
import time 

# === CONFIGURATION ===
# Paths to the certificates you want to check
cert_paths = [
    "/etc/maglev/.pki/etcd-peer.pem",
    "/etc/maglev/.pki/etcd-client.pem",
    "/etc/maglev/.pki/apiserver.crt"
]

# Temporary directory for auxiliary files
TMP_DIR = "/tmp/regen_certificates"

# Log file path
LOG_FILE = "/tmp/regen_certificates/regen_certificates.log"

# Create temporary directory if it doesn't exist
os.makedirs(TMP_DIR, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()  # Show logs on console too
    ]
)


# === FUNCTIONS ===
def get_cert_expiration_date(cert_path):
    """Returns the expiration date of the certificate"""
    try:
        with open(cert_path, 'rt') as f:
            cert_data = f.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
        expiration_bytes = cert.get_notAfter()
        expiration_str = expiration_bytes.decode('utf-8')

        if expiration_str.endswith('Z'):
            expiration_str = expiration_str[:-1]

        naive_date = datetime.strptime(expiration_str, "%Y%m%d%H%M%S")
        aware_date = naive_date.replace(tzinfo=timezone.utc)

        return aware_date
    except Exception as e:
        logging.error(f"Could not read {cert_path}: {e}")
        return None


def is_cert_expired(cert_expiration_date):
    """Compares the expiration date with the current date"""
    if cert_expiration_date is None:
        return True
    now = datetime.now(cert_expiration_date.tzinfo)
    return now >= cert_expiration_date


def create_cnf_file(cert_path, cnf_path, cn="etcd-peer", extra_sections=None):
    """Creates a CNF file using SANs from the old certificate."""
    try:
        # Extract certificate info
        cmd = ["openssl", "x509", "-noout", "-text", "-in", cert_path]
        output = subprocess.check_output(cmd).decode("utf-8")

        in_subject_alt_name = False
        san_lines = []
        in_extensions = False
        extensions = []

        # Extract SANs safely
        for line in output.splitlines():
            if "Subject Alternative Name" in line:
                in_subject_alt_name = True
                continue
            elif in_subject_alt_name and line.strip() == "":
                in_subject_alt_name = False

            if in_subject_alt_name:
                if re.search(r'^(DNS|IP|URI|email|RID):', line.strip()):
                    san_line = line.strip().replace(", ", ",").replace(" ,", ",")
                    san_lines.extend(san_line.split(","))

            # Capture extensions
            if in_extensions:
                if line.strip().startswith("Signature Algorithm:") or re.match(r"^\s*$", line):
                    in_extensions = False
                else:
                    extensions.append(line.strip())

            if "Extensions:" in line:
                in_extensions = True
                continue

        # Default sections
        default_sections = [
            "[ req ]",
            "req_extensions = v3_req",
            "distinguished_name = req_distinguished_name",
            "default_bits = 2048",
            "default_md = sha512",
            "prompt = no",
            "",
            "[ req_distinguished_name ]",
            f"CN = {cn}",
            "",
            "[ v3_req ]"
        ]

        # Add extracted extensions
        if extensions:
            default_sections += extensions

        if extra_sections:
            default_sections += extra_sections

        default_sections += [
            "",
            "subjectAltName = @alt_names",
            "",
            "[ alt_names ]"
        ]

        # Write CNF file
        with open(cnf_path, "w") as f:
            f.write("\n".join(default_sections) + "\n\n")

            dns_count = 1
            ip_count = 1
            for item in san_lines:
                item = item.strip()
                if item.startswith("DNS:"):
                    f.write(f"DNS.{dns_count} = {item[4:]}\n")
                    dns_count += 1
                elif item.startswith("IP Address:"):
                    ip_value = item[11:].strip()
                    f.write(f"IP.{ip_count} = {ip_value}\n")
                    ip_count += 1
                elif item.startswith("IP:"):
                    ip_value = item[3:].strip()
                    f.write(f"IP.{ip_count} = {ip_value}\n")
                    ip_count += 1
                elif item:
                    logging.warning(f"Ignoring unrecognized SAN entry: {item}")

        logging.info(f"Created CNF file at {cnf_path}")
    except Exception as e:
        logging.error(f"Failed to create CNF file: {e}")


def regenerate_etcd_peer_cert(cert_path):
    """Regenerates the first certificate (etcd-peer) if expired."""
    logging.warning(f"Starting regeneration process for {cert_path}...")

    try:
        # --- Backup Cert ---
        backup_path = os.path.join(TMP_DIR, "old_etcd-peer.pem")
        subprocess.run(["cp", "-p", cert_path, backup_path], check=True)
        logging.info(f"Backup created at {backup_path}")

        # --- Create CNF: used to generate CSR ---
        cnf_path = os.path.join(TMP_DIR, "cnf_etcd-peer.cnf")
        create_cnf_file(
            backup_path,
            cnf_path,
            cn="etcd-peer",
            extra_sections=[
                "basicConstraints = CA:FALSE",
                "keyUsage = digitalSignature, nonRepudiation, keyEncipherment",
                "extendedKeyUsage= serverAuth, clientAuth",
            ]
        )

        # Retrieve encrypted passphrase
        passphrase_path = "/etc/maglev/.pki/encrypted_passphrase.txt"
        try:
            encrypted_passphrase = subprocess.check_output([
                "sudo", "magluv-keymgr", "-d", "-f", passphrase_path
            ]).decode("utf-8").strip()

            if not encrypted_passphrase:
                logging.error("The passphrase returned by magluv-keymgr is empty.")
                return
            logging.info("Retrieved encrypted_passphrase")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to retrieve passphrase with magluv-keymgr: {e}")
            return

        # Generate CSR
        csr_path = os.path.join(TMP_DIR, "csr_etcd-peer.csr")
        key_path = "/etc/maglev/.pki/etcd-peer-key.pem"
        cmd = [
            "sudo", "openssl", "req", "-config", cnf_path,
            "-key", key_path, "-new", "-out", csr_path
        ]

        logging.info("Running command: %s", " ".join(cmd))

        # Save passphrase to secure temp file
        passphrase_file = os.path.join(TMP_DIR, ".key_passphrase")
        with open(passphrase_file, "w") as f:
            f.write(encrypted_passphrase + "\n")
        os.chmod(passphrase_file, 0o600)

        # Add -passin parameter
        cmd_with_pass = cmd + ["-passin", f"file:{passphrase_file}"]

        try:
            result = subprocess.run(
                cmd_with_pass,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                check=True
            )
            logging.info(f"CSR generated at {csr_path}")
        except subprocess.CalledProcessError as e:
            logging.error("Error generating CSR:")
            logging.error(e.stderr)
            return
        finally:
            # Remove temp file securely
            try:
                os.remove(passphrase_file)
            except Exception as e:
                logging.warning(f"Could not remove temporary passphrase file: {e}")


        if result.returncode == 0:
            logging.info(f"CSR generated at {csr_path}")
        else:
            logging.error("Error generating CSR:")
            logging.error(result.stderr)
            return

        # Generate new certificate
        new_cert_path = os.path.join(TMP_DIR, "new_etcd-peer.pem")
        ca_cert = "/etc/maglev/.pki/ca.crt"
        ca_key = "/etc/maglev/.pki/ca.key"

        subprocess.run([
            "sudo", "openssl", "x509", "-req", "-days", "360",
            "-in", csr_path,
            "-CA", ca_cert,
            "-CAkey", ca_key,
            "-CAcreateserial",
            "-out", new_cert_path,
            "-extfile", cnf_path,
            "-extensions", "v3_req"
        ], check=True)
        logging.info(f"New certificate created at {new_cert_path}")

        # --- SET PERMISSIONS AND COPY FINAL CERTIFICATE ---
        subprocess.run(["chmod", "444", new_cert_path], check=True)
        subprocess.run(["chown", "root:root", new_cert_path], check=True)

        subprocess.run(["cp", "-p", new_cert_path, cert_path], check=True)
        logging.info(f"Certificate replaced at {cert_path}")

    except Exception as e:
        logging.error(f"Unexpected error during regeneration of {cert_path}: {e}")


def regenerate_etcd_client_cert(cert_path, cn_value, key_path, new_cert_name):
    """
    Regenerates a custom certificate without requiring a passphrase.
    """
    logging.warning(f" Starting regeneration process for {cert_path}...")

    try:

        # --- Backup Cert ---
        backup_path = os.path.join(TMP_DIR, "old_etcd-client.pem")
        subprocess.run(["cp", "-p", cert_path, backup_path], check=True)
        logging.info(f"Backup created at {backup_path}")

        # --- Create CNF: used to generate CSR ---
        cnf_path = os.path.join(TMP_DIR, "cnf_etcd-client.cnf")
        create_cnf_file(
            backup_path,
            cnf_path,
            cn="etcd-client",
            extra_sections=[
                "basicConstraints = CA:FALSE",
                "keyUsage = digitalSignature, nonRepudiation, keyEncipherment",
                "extendedKeyUsage= serverAuth, clientAuth",
            ]
        )

        # --- GENERATE CSR ---
        csr_path = os.path.join(TMP_DIR, f"csr_{new_cert_name}.csr")
        cmd = [
            "sudo", "openssl", "req", "-config", cnf_path,
            "-key", key_path, "-new", "-out", csr_path
        ]

        logging.info("Running command: %s", " ".join(cmd))
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=True
        )

        if result.returncode == 0:
            logging.info(f"CSR generated at {csr_path}")
        else:
            logging.error("Error generating CSR:")
            logging.error(result.stderr)
            return

        # Generate new certificate
        new_cert_path = os.path.join(TMP_DIR, "new_etcd-client.pem")
        ca_cert = "/etc/maglev/.pki/ca.crt"
        ca_key = "/etc/maglev/.pki/ca.key"

        subprocess.run([
            "sudo", "openssl", "x509", "-req", "-days", "360",
            "-in", csr_path,
            "-CA", ca_cert,
            "-CAkey", ca_key,
            "-CAcreateserial",
            "-out", new_cert_path,
            "-extfile", cnf_path,
            "-extensions", "v3_req"
        ], check=True)
        logging.info(f"New certificate created at {new_cert_path}")

        # --- SET PERMISSIONS AND COPY FINAL CERTIFICATE ---
        subprocess.run(["chmod", "444", new_cert_path], check=True)
        subprocess.run(["chown", "root:root", new_cert_path], check=True)

        subprocess.run(["cp", "-p", new_cert_path, cert_path], check=True)
        logging.info(f"Certificate replaced at {cert_path}")

    except Exception as e:
        logging.error(f"Unexpected error during regeneration of {cert_path}: {e}")


def regenerate_apiserver_cert(cert_path):
    """Regenerates apiserver.crt using two different .cnf files."""
    logging.warning(f"Starting regeneration process for {cert_path}...")

    try:
        # --- Backup Cert ---
        backup_path = os.path.join(TMP_DIR, "old_apiserver.crt")
        subprocess.run(["cp", "-p", cert_path, backup_path], check=True)
        logging.info(f"Backup created at {backup_path}")

        # Define paths
        cnf_1_path = os.path.join(TMP_DIR, "cnf_apiserver_1.cnf")
        cnf_2_path = os.path.join(TMP_DIR, "cnf_apiserver_2.cnf")
        csr_path = os.path.join(TMP_DIR, "csr_apiserver.csr")
        new_cert_path = os.path.join(TMP_DIR, "new_apiserver.crt")
        key_path = "/etc/maglev/.pki/apiserver.key"

        # --- FIRST CNF: used to generate CSR ---
        create_cnf_file(
            backup_path,
            cnf_1_path,
            cn="kube-apiserver",
            extra_sections=[
                "keyUsage = critical, keyEncipherment, digitalSignature",
                "extendedKeyUsage=serverAuth"
            ]
        )

        # --- GENERATE CSR ---
        cmd_csr = [
            "sudo", "openssl", "req", "-config", cnf_1_path,
            "-key", key_path, "-new", "-out", csr_path
        ]

        logging.info("Running command: %s", " ".join(cmd_csr))
        result = subprocess.run(
            cmd_csr,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=True
        )

        if result.returncode == 0:
            logging.info(f"CSR generated at {csr_path}")
        else:
            logging.error("Error generating CSR:")
            logging.error(result.stderr)
            return

        # --- SECOND CNF: used to sign the certificate ---
        create_cnf_file(
            backup_path,
            cnf_2_path,
            cn="kube-apiserver",
            extra_sections=[
                "keyUsage = critical, keyEncipherment, digitalSignature",
                "extendedKeyUsage=serverAuth",
                "basicConstraints = critical, CA:FALSE",
                "authorityKeyIdentifier = keyid"
            ]
        )

        # --- SIGN THE CERTIFICATE ---
        ca_cert = "/etc/maglev/.pki/ca.crt"
        ca_key = "/etc/maglev/.pki/ca.key"

        subprocess.run([
            "sudo", "openssl", "x509", "-req", "-days", "360",
            "-in", csr_path,
            "-CA", ca_cert,
            "-CAkey", ca_key,
            "-CAcreateserial",
            "-out", new_cert_path,
            "-extfile", cnf_2_path,
            "-extensions", "v3_req"
        ], check=True)
        logging.info(f"New certificate created at {new_cert_path}")

        # --- SET PERMISSIONS AND COPY FINAL CERTIFICATE ---
        subprocess.run(["chmod", "644", new_cert_path], check=True)
        subprocess.run(["chown", "root:root", new_cert_path], check=True)

        subprocess.run(["cp", "-p", new_cert_path, cert_path], check=True)
        logging.info(f"Certificate replaced at {cert_path}")

    except Exception as e:
        logging.error(f"Unexpected error during regeneration of {cert_path}: {e}")

def wait_for_crictl(timeout=300, interval=10):
    """
    Espera hasta que 'crictl ps' funcione o se alcance el timeout (en segundos).
    :param timeout: Máximo tiempo de espera en segundos
    :param interval: Intervalo de verificación en segundos
    """
    logging.info(f" Waiting for 'crictl' to become ready (max {timeout // 60} min)...")

    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            result = subprocess.run(
                ["sudo", "crictl", "ps"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                check=True
            )
            logging.info("'crictl' is now available.")
            return True
        except subprocess.CalledProcessError:
            logging.warning("'crictl' not ready yet. Retrying in %s seconds...", interval)
            time.sleep(interval)

    logging.error("Timeout reached. 'crictl' did not become available.")
    return False

def is_tmux_session_active(session_name):
    """Check if a tmux session is still running."""
    try:
        result = subprocess.run(
            ["tmux", "list-sessions"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=False
        )
        return session_name in result.stdout
    except Exception:
        return False

# === MAIN ===
if __name__ == "__main__":
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logging.info(f"\n Current system date: {current_time}\n")

    all_success = True

    # Process each certificate
    for i, cert_path in enumerate(cert_paths):
        expiration_date = get_cert_expiration_date(cert_path)
        if expiration_date:
            expired = is_cert_expired(expiration_date)
            expiration_str = expiration_date.strftime("%Y-%m-%d %H:%M:%S %z")
            status = "is expired" if expired else "is NOT expired"
            logging.info(f" Certificate: {cert_path} -> The certificate {status}.")
            logging.info(f"   > Expiration date: {expiration_str}\n")

            try:
                if i == 0 and expired:
                    logging.warning(" First certificate is expired. Regenerating...")
                    regenerate_etcd_peer_cert(cert_path)
                elif i == 1 and expired:
                    logging.warning("  Second certificate is expired. Regenerating...")
                    regenerate_etcd_client_cert(
                        cert_path=cert_path,
                        cn_value="etcd-client",
                        key_path="/etc/maglev/.pki/etcd-client-key.pem",
                        new_cert_name="etcd-client"
                    )
                elif i == 2 and expired:
                    logging.warning("  Third certificate is expired. Regenerating...")
                    regenerate_apiserver_cert(cert_path)

            except Exception as e:
                logging.error(f"Error processing certificate {cert_path}: {e}")
                all_success = False
        else:
            logging.error(f" Certificate: {cert_path} -> Could not verify.\n")
            all_success = False

    # Only proceed with post-cert tasks if all certs were successfully regenerated
    if all_success:
        logging.info("ETCD and ApiServer certificates were successfully regenerated.")
        logging.info("Proceeding with post-regeneration tasks...")
        logging.info(" Running command: sudo maglev-config certs info")
        subprocess.run(["sudo", "maglev-config", "certs", "info"], check=True)

        # Step 1: Restart services
        try:
            logging.info(" Restarting services: docker kubelet")
            subprocess.run(["sudo", "systemctl", "restart", "docker", "kubelet"], check=True)
            logging.info(" Services restarted successfully.")
        except subprocess.CalledProcessError as e:
            logging.error(f" Failed to restart services: {e}")
            all_success = False

        # Step 2: Wait for crictl to be ready
        if all_success:
            if not wait_for_crictl(timeout=300, interval=10):
                logging.error(" 'docker' is not responding. Aborting container cleanup.")
                all_success = False

        # Step 3: Execute container cleanup commands first
        commands = [
            ("sudo docker ps -a | grep -e decrypt-private-key -e kube-apiserver -e kube-controller-manager -e kube-scheduler", "List containers to remove"),
            ("sudo docker rm $(sudo crictl ps -a | grep decrypt-private-key | awk '{print $1}')", "Remove decrypt-private-key containers"),
            ("sudo docker stop $(sudo crictl ps -a | grep etcd | awk '{print $1}')", "Stop etcd containers"),
            ("sudo docker rm $(sudo crictl ps -a | grep etcd | awk '{print $1}')", "Remove etcd containers"),
            ("sudo docker stop $(sudo crictl ps -a | grep kube-apiserver | awk '{print $1}')", "Stop kube-apiserver containers"),
            ("sudo docker rm $(sudo crictl ps -a | grep kube-apiserver | awk '{print $1}')", "Remove kube-apiserver containers")
        ]

        logging.info(" Executing final steps: container/service clean-up and restart")

        for cmd, description in commands:
            try:
                logging.info(f" {description}")
                result = subprocess.run(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    check=True
                )
                if result.returncode == 0:
                   if result.stdout.strip():
                        logging.info("STDOUT:\n%s", result.stdout)
                   if result.stderr.strip():
                        logging.warning("STDERR:\n%s", result.stderr)
                else:
                    if result.stderr.strip():
                        logging.warning(f" Partial failure in {description}:")
                        logging.warning("STDERR:\n%s", result.stderr)

            except Exception as e:
                logging.error(f" Error executing command: {cmd} -> {e}")
                all_success = False
                continue 

        # Step 4: Backup .kube/config files
        if all_success:
            backup_dir = os.path.join(TMP_DIR, "backup_configs")
            os.makedirs(backup_dir, exist_ok=True)
            try:
                logging.info(" Creating backups of .kube/config files...")
                subprocess.run(["cp", "-p", "/etc/kubernetes/admin.conf", os.path.join(backup_dir, "BK_admin-config.conf")], check=True)
                subprocess.run(["cp", "-p", "/home/maglev/.kube/config", os.path.join(backup_dir, "BK_kube-config")], check=True)
                subprocess.run(["cp", "-p", "/root/.kube/config", os.path.join(backup_dir, "BK_root-config")], check=True)
                logging.info(" Backups created successfully.")
            except subprocess.CalledProcessError as e:
                logging.error(f" Failed to create config backups: {e}")
                all_success = False

        # Step 5: Check expiration date of admin.conf's certificate
        if all_success:
            try:
                # Extract current certificate from admin.conf
                k8s_cert_b64 = "/tmp/regen_certificates/old_client-certificate-data.txt"
                k8s_key_pem = "/tmp/regen_certificates/kubernetes-admin-key.pem"
                k8s_cert_pem = "/tmp/regen_certificates/old_kubernetes-admin.pem"

                logging.info(" Extracting client certificate and key from admin.conf...")
                # Extract the key
                subprocess.run([
                    "bash", "-c",
                    f"cat /etc/kubernetes/admin.conf | grep client-key-data | awk '{{print $2}}' | base64 -d > {k8s_key_pem}"
                ], check=True)

                # Extract the certificate data (base64 + PEM)
                subprocess.run([
                    "bash", "-c",
                    f"cat /etc/kubernetes/admin.conf | grep client-certificate-data | awk '{{print $2}}' > {k8s_cert_b64}"
                ], check=True)
                subprocess.run([
                    "bash", "-c",
                    f"cat {k8s_cert_b64} | base64 -d > {k8s_cert_pem}"
                ], check=True)

                # Get notAfter date
                result = subprocess.run(
                    ["openssl", "x509", "-noout", "-dates", "-in", k8s_cert_pem],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    check=True
                )
                logging.info("Certificate dates from admin.conf:\n%s", result.stdout)

                # Parse notAfter
                not_after_line = [line for line in result.stdout.splitlines() if line.startswith("notAfter=")]
                if not_after_line:
                    not_after_str = not_after_line[0].replace("notAfter=", "").strip()
                    cert_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)

                    if now >= cert_date:
                        logging.warning("  Certificate in admin.conf is expired. Regenerating new one...")
                        
                        # Define paths
                        cnf_1_path = os.path.join(TMP_DIR, "cnf_kubernetes-admin_1.cnf")
                        cnf_2_path = os.path.join(TMP_DIR, "cnf_kubernetes-admin_2.cnf")
                        csr_path = os.path.join(TMP_DIR, "csr_kubernetes-admin.csr")
                        new_cert_path = os.path.join(TMP_DIR, "new_kubernetes-admin.pem")
                        encrypted_cert_path = os.path.join(TMP_DIR, "encripted_kubernetes-admin.pem")

                        # --- GENERATE CNF 1 ---
                        with open(cnf_1_path, "w") as f:
                            f.write('''[ req ]
req_extensions = v3_req
distinguished_name = req_distinguished_name
default_bits = 2048
default_md = sha512
prompt = no

[ req_distinguished_name ]
O = system:masters
CN = kubernetes-admin

[ v3_req ]
keyUsage = critical, keyEncipherment, digitalSignature
extendedKeyUsage= clientAuth
basicConstraints = critical, CA:FALSE
''')
                        logging.info(f"Created CNF file at {cnf_1_path}")

                        # --- GENERATE CNF 2 ---
                        with open(cnf_2_path, "w") as f:
                            f.write('''[ req ]
req_extensions = v3_req
distinguished_name = req_distinguished_name
default_bits = 2048
default_md = sha512
prompt = no

[ req_distinguished_name ]
O = system:masters
CN = kubernetes-admin

[ v3_req ]
keyUsage = critical, keyEncipherment, digitalSignature
extendedKeyUsage= clientAuth
basicConstraints = critical, CA:FALSE
authorityKeyIdentifier = keyid
''')
                        logging.info(f"Created CNF file at {cnf_2_path}")

                        # --- GENERATE CSR ---
                        logging.info(" Generating CSR for kubernetes-admin...")
                        subprocess.run([
                            "openssl", "req", "-config", cnf_1_path,
                            "-key", k8s_key_pem, "-new", "-out", csr_path
                        ], check=True)
                        logging.info(f"CSR generated at {csr_path}")

                        # --- GENERATE NEW CERTIFICATE ---
                        logging.info(" Generating new kubernetes-admin certificate...")
                        ca_cert = "/etc/maglev/.pki/ca.crt"
                        ca_key = "/etc/maglev/.pki/ca.key"

                        subprocess.run([
                            "openssl", "x509", "-req", "-days", "365",
                            "-in", csr_path,
                            "-CA", ca_cert,
                            "-CAkey", ca_key,
                            "-out", new_cert_path,
                            "-extfile", cnf_2_path,
                            "-extensions", "v3_req"
                        ], check=True)
                        logging.info(f"New kubernetes-admin cert created at {new_cert_path}")

                        # --- ENCODE TO BASE64 ---
                        logging.info(" Encoding new certificate to base64...")
                        result = subprocess.run(
                            ["base64", "-w", "0", new_cert_path],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True,
                            check=True
                        )
                        if result.returncode == 0:
                            encrypted_cert_data = result.stdout.strip()
                            logging.info(" Certificate successfully encoded to base64.")
                        else:
                            logging.error(" Failed to encode certificate to base64.")
                            logging.error("STDERR:\n%s", result.stderr)
                            all_success = False
                        
                        # --- UPDATE admin.conf FILE ---
                        logging.info(" Updating /etc/kubernetes/admin.conf...")
                        try:
                            # We use sed to replace only the 'client-certificate-data'
                            subprocess.run(
                                f"sudo sed -i 's|\\(client-certificate-data:\\s*\\).*|\\1{encrypted_cert_data}|' /etc/kubernetes/admin.conf",
                                shell=True,
                                check=True,
                                executable="/bin/bash"
                            )
                            logging.info(" admin.conf updated successfully.")
                        except subprocess.CalledProcessError as e:
                            logging.error(f" Failed to update admin.conf: {e}")
                            all_success = False

                        # --- CONFIRMATION ---
                        logging.info(" Checking updated certificate dates...")
                        result = subprocess.run(
                            ["bash", "-c",
                             "cat /etc/kubernetes/admin.conf | grep client-certificate-data | awk '{print $2}' | base64 -d | openssl x509 -noout -dates"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True,
                            check=True
                        )
                        logging.info(" New certificate dates:\n%s", result.stdout)

                    else:
                        logging.info(" Certificate in admin.conf is valid.")
                else:
                    logging.warning("Could not extract notAfter date from admin.conf")
                    all_success = False
            except Exception as e:
                logging.error(f" Error extracting certificate dates from admin.conf: {e}")
                all_success = False

        # Step 6: Update .kube/config files
        if all_success:
            try:
                logging.info(" Updating .kube/config files...")
                subprocess.run(["cp", "/etc/kubernetes/admin.conf", "/home/maglev/.kube/config"], check=True)
                subprocess.run(["cp", "/etc/kubernetes/admin.conf", "/root/.kube/config"], check=True)

                logging.info(" Setting permissions on .kube/config files...")
                subprocess.run(["chmod", "640", "/home/maglev/.kube/config"], check=True)
                subprocess.run(["chmod", "600", "/root/.kube/config"], check=True)

                logging.info(" Setting ownership on .kube/config files...")
                subprocess.run(["chown", "maglev:maglev", "/home/maglev/.kube/config"], check=True)
                subprocess.run(["chown", "root:root", "/root/.kube/config"], check=True)

                logging.info(" .kube/config files updated and secured.")
            except subprocess.CalledProcessError as e:
                logging.error(f" Failed to update .kube/config files: {e}")
                all_success = False


        # Step 7 Backup /tmp/regen_certificates to /data/tmp/
        if all_success:
            try:
                logging.info(" Creating backup of %s to /data/tmp/", TMP_DIR)
                subprocess.run(["sudo", "cp", "-rp", TMP_DIR, "/data/tmp/"], check=True)
                logging.info(" Backup completed: %s -> /data/tmp/", TMP_DIR)
            except subprocess.CalledProcessError as e:
                logging.warning(f"  Failed to backup {TMP_DIR} to /data/tmp/: {e}")

        # Step 8: Run maglev-config certs refresh in a tmux session
        TMUX_SESSION_NAME = "regen_certs_refresh"
        if all_success:
            logging.info(" Starting 'maglev-config certs refresh' in background via tmux...")
            try:
                subprocess.run([
                    "tmux", "new-session", "-d", "-s", TMUX_SESSION_NAME,
                    "sudo maglev-config certs refresh && echo ' Done'; sleep 10"
                ], check=True)

                logging.info(f" TMUX Session '{TMUX_SESSION_NAME}' started in background.")
            except subprocess.CalledProcessError as e:
                logging.error(f" Failed to start tmux session: {e}")
                all_success = False

        # Wait 5 minutes after refresh starts
        if all_success:
            logging.info(" Waiting up to 10 minutes for certificate regeneration to complete...")
            time.sleep(60)
            logging.info(" Waiting up to 9 minutes for certificate regeneration to complete...")
            time.sleep(60)
            logging.info(" Waiting up to 8 minutes for certificate regeneration to complete...")
            time.sleep(60)
            logging.info(" Waiting up to 7 minutes for certificate regeneration to complete...")
            time.sleep(60)
            logging.info(" Waiting up to 6 minutes for certificate regeneration to complete...")
            time.sleep(60)
            logging.info(" Waiting up to 5 minutes for certificate regeneration to complete...")
            time.sleep(60)
            logging.info(" Waiting up to 4 minutes for certificate regeneration to complete...")
            time.sleep(60)
            logging.info(" Waiting up to 3 minutes for certificate regeneration to complete...")
            time.sleep(60)
            logging.info(" Waiting up to 2 minutes for certificate regeneration to complete...")
            time.sleep(60)
            logging.info(" Waiting up to 1 minutes for certificate regeneration to complete...")
            time.sleep(60)


        # Step 9: Run 'maglev-config certs info' and show output
        if all_success:
            logging.info(" Running command: sudo maglev-config certs info")
            try:
                result = subprocess.run(
                    ["sudo", "maglev-config", "certs", "info"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    check=False,
                    timeout=60
                )

                output = result.stdout.strip()
                error_output = result.stderr.strip()

                if output:
                    logging.info("Certificate status output:\n%s", output)
                if error_output:
                    logging.warning("STDERR from 'maglev-config certs info':\n%s", error_output)

            except subprocess.CalledProcessError as e:
                logging.warning(" Command 'maglev-config certs info' exited with errors: %s", e)
            except subprocess.TimeoutExpired:
                logging.error(" Command 'maglev-config certs info' timed out after 60 seconds.")


        # Step 10: Kill tmux session if still active
        TMUX_SESSION_NAME = "regen_certs_refresh"
        if is_tmux_session_active(TMUX_SESSION_NAME):
            logging.warning(f" Tmux session '{TMUX_SESSION_NAME}' is still running. Killing it...")
            try:
                subprocess.run(["tmux", "kill-session", "-t", TMUX_SESSION_NAME], check=True)
            except subprocess.CalledProcessError as e:
                logging.warning(f" Could not kill tmux session: {e}")



        # If any cert failed to regenerate, exit early
        if not all_success:
            logging.error("""
 Some certificates were NOT properly regenerated.
   It seems there was an issue during certificate refresh.
   Please inspect with:
      sudo maglev-config certs info

   Aborting process. Manual intervention may be needed.
""")
            # Exit early
            exit(1)

        # Final message
        if all_success:
            logging.info("""
 Process completed successfully. 
 Certificates are generation itself and PODs have been restarted.
   The cluster should come back up shortly.

  If you do NOT see GlusterFS mounted, check with:
   df -h

   If mounts are missing, reboot the server and be patient.
""")
        else:
            logging.error(" Some steps failed during post-certificate regeneration. Manual intervention may be needed.")
