import grpc
import policy_pb2
import policy_pb2_grpc

SERVER_IP = '192.168.2.62'
SERVER_PORT = '50051'
CERT_PATH = "keys/server.crt"

def get_grpc_channel():
    with open(CERT_PATH, "rb") as cert_file:
        trusted_certs = cert_file.read()
    credentials = grpc.ssl_channel_credentials(root_certificates=trusted_certs)
    return grpc.secure_channel(f'{SERVER_IP}:{SERVER_PORT}', credentials)
