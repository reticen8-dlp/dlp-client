import grpc
import policy_pb2
import policy_pb2_grpc
import platform
import socket
import os

def register_client(agent_id):

    with open("keys/server.crt", "rb") as cert_file:
        trusted_certs = cert_file.read()
        credentials = grpc.ssl_channel_credentials(root_certificates=trusted_certs)
    
    channel = grpc.secure_channel('192.168.2.62:50051',credentials)

    stub = policy_pb2_grpc.ClientServiceStub(channel, )

    device_name = socket.gethostname()
    os_version = platform.version()
    username = os.getlogin()

    print(f"Sending request with: \nAgent ID: {agent_id}\nDevice Name: {device_name}\nOS Version: {os_version}\nUsername: {username}")

    client_details = policy_pb2.ClientDetails(
        agent_id=agent_id,
        device_name=device_name,
        os_version=os_version,
        username=username
    )

    try:
        
        response = stub.RegisterClient(client_details)
        print("Client registered successfully:", response.status, response.message)
    except grpc.RpcError as e:
        print(f"RPC failed: {e.code()} - {e.details()}")

if __name__ == "__main__":
    agent_id = "agent-006" 
    register_client(agent_id)
