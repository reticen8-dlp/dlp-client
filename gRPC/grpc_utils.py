import grpc
import os,sys
import policy_pb2
import policy_pb2_grpc

SERVER_IP = '192.168.2.62'
SERVER_PORT = '50051'


def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS  # PyInstaller temporary folder
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


CERT_PATH = resource_path("gRPC/keys/server.crt")

def get_grpc_channel():
    with open(CERT_PATH, "rb") as cert_file:
        trusted_certs = cert_file.read()
    credentials = grpc.ssl_channel_credentials(root_certificates=trusted_certs)
    return grpc.secure_channel(f'{SERVER_IP}:{SERVER_PORT}', credentials)
