import grpc
import gRPC.policy_pb2 as policy_pb2
import gRPC.policy_pb2_grpc as policy_pb2_grpc
import platform
import socket
import os
import json
from gRPC.logger import send_log
from gRPC.grpc_utils import get_grpc_channel

CLIENT_ID_FILE = "client_id.txt"
AGENT_ID = "agent-008"

def register_client():
    """Registers the client and saves the client ID."""
    channel = get_grpc_channel()
    stub = policy_pb2_grpc.ClientServiceStub(channel)  # FIXED: Correct service stub

    device_name = socket.gethostname()
    os_version = platform.version()
    username = os.getlogin()

    client_details = policy_pb2.ClientDetails(
        device_name=device_name,
        os_version=os_version,
        username=username
    )

    try:
        response = stub.RegisterClient(client_details)
        if response.status == "Success":
            client_id = response.client_id
            print("agent_id")
            agent_id = response.agent_id
            print("Client registered successfully:", response.status, response.message)
            print("Received Client ID:", client_id)
            print("Received Agent ID:", agent_id)

            with open(CLIENT_ID_FILE, "w") as file:
                file.write(f"client_id={client_id}\nagent_id={agent_id}")

            send_log(client_id, agent_id, "INFO", "Client registered successfully")  # Logging success
            return client_id,agent_id
        else:
            print("Client registration failed:", response.status, response.message)
            send_log("N/A", "N/A", "ERROR", "Client registration failed")  # Logging failure
            return None,None
    except grpc.RpcError as e:
        
        print(f"RPC failed: {e.code()} - {e.details()}")
        send_log("N/A", "N/A", "ERROR", f"RPC failed: {e.code()} - {e.details()}")
        return None,None

def read_policy(client_id, agent_id):
    """Fetch policy from the server."""
    channel = get_grpc_channel()
    stub = policy_pb2_grpc.ClientServiceStub(channel)  # FIXED: Correct service stub

    request = policy_pb2.PolicyRequest(client_id=client_id, agent_id=agent_id)

    try:
        response = stub.GetPolicy(request)

        if response.status == "Success":
            # print("Policy fetched successfully:", response.message)
            policy_data = json.loads(response.policy_data)
            # print(f"Decoded Policy Data: {policy_data}")

            send_log(client_id, agent_id, "INFO", "Policy successfully fetched")  # Logging success
            return policy_data
        else:
            print("Failed to fetch policy:", response.status, response.message)
            send_log(client_id, agent_id, "ERROR", "Policy fetch failed")  # Logging failure
    except grpc.RpcError as e:
        print(f"RPC failed: {e.code()} - {e.details()}")
        send_log(client_id, agent_id, "ERROR", f"RPC failed: {e.code()} - {e.details()}")

if __name__ == "__main__":
    if os.path.exists(CLIENT_ID_FILE):
       with open(CLIENT_ID_FILE, "r") as file:
        lines = file.readlines()  # Read all lines
        client_id = None
        agent_id = None
        for line in lines:
            line = line.strip()
            if line.startswith("client_id="):
                client_id = line.split("=")[1]
            elif line.startswith("agent_id="):
                agent_id = line.split("=")[1]
        if client_id is None or agent_id is None:
            print("Warning: client_id or agent_id missing or incomplete in file. Registering new client.")
            client_id, agent_id = register_client()

    if client_id and agent_id:
        read_policy(client_id,agent_id)
    else:
        print("Failed to register client or fetch policy.")
