# Only tested once
# be warned documentation found from stackoverflow


import azure.functions as func
import azure.cosmos.cosmos_client as cosmos_client
from azure.servicebus import ServiceBusClient, ServiceBusMessage
import json
import os
import logging
from typing import Dict, Any
import numpy as np
from datetime import datetime

# Configuration settings loaded from environment variables
# Important 90% occur from misconfiguration to these
COSMOS_ENDPOINT = os.environ.get("COSMOS_ENDPOINT")
COSMOS_KEY = os.environ.get("COSMOS_KEY")
DATABASE_NAME = "IoTDataDB"
CONTAINER_NAME = "Telemetry"
SERVICE_BUS_CONN_STR = os.environ.get("SERVICE_BUS_CONNECTION_STRING")
SERVICE_BUS_QUEUE = "anomaly-notifications"

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def initialize_cosmos_client():
    """Initialize and return a Cosmos DB client."""
    try:
        client = cosmos_client.CosmosClient(COSMOS_ENDPOINT, COSMOS_KEY)
        database = client.get_database_client(DATABASE_NAME)
        container = database.get_container_client(CONTAINER_NAME)
        return client, database, container
    except Exception as e:
        logger.error(f"Failed to initialize Cosmos client: {str(e)}")
        raise

def initialize_service_bus_client():
    """Initialize and return a Service Bus client."""
    try:
        return ServiceBusClient.from_connection_string(SERVICE_BUS_CONN_STR)
    except Exception as e:
        logger.error(f"Failed to initialize Service Bus client: {str(e)}")
        raise

def detect_anomaly(data: Dict[str, Any]) -> bool:
    """
    Detect anomalies in telemetry data using a simple statistical method.
    Returns True if an anomaly is detected, False otherwise.
    """
    try:
        # Extract temperature from telemetry data
        temperature = data.get("temperature", 0.0)
        
        # Define a simple thresholded-based anomaly detection
        # In a real scenario, you'd use a more sophisticated model (e.g., ML-based)
        mean_temp = 25.0  # Example mean temperature
        std_dev = 5.0     # Example standard deviation
        z_score = abs(temperature - mean_temp) / std_dev
        
        # Consider it an anomaly if z-score > 3 (outside 3 standard deviations may need to be adjusted)
        return z_score > 3
    except Exception as e:
        logger.error(f"Error in anomaly detection: {str(e)}")
        return False

def store_telemetry(container, telemetry: Dict[str, Any]):
    """Store telemetry data in Cosmos DB."""
    try:
        # Add timestamp and ID for Cosmos DB
        telemetry["id"] = f"{telemetry['device_id']}_{datetime.utcnow().isoformat()}"
        telemetry["timestamp"] = datetime.utcnow().isoformat()
        container.upsert_item(telemetry)
        logger.info(f"Stored telemetry for device {telemetry['device_id']}")
    except Exception as e:
        logger.error(f"Failed to store telemetry: {str(e)}")
        raise

def send_notification(service_bus_client, telemetry: Dict[str, Any]):
    """Send anomaly notification to Service Bus queue."""
    try:
        with service_bus_client.get_queue_sender(SERVICE_BUS_QUEUE) as sender:
            message = ServiceBusMessage(
                json.dumps({
                    "device_id": telemetry["device_id"],
                    "temperature": telemetry["temperature"],
                    "timestamp": telemetry["timestamp"],
                    "alert": "Anomaly detected in temperature reading"
                })
            )
            sender.send_messages(message)
            logger.info(f"Sent anomaly notification for device {telemetry['device_id']}")
    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")
        raise

def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function to process IoT telemetry, detect anomalies, store data in Cosmos DB,
    and send notifications via Service Bus for anomalies.
    """
    logger.info("Processing IoT telemetry request")

    try:
        # Parse incoming telemetry data
        req_body = req.get_json()
        telemetry = req_body if isinstance(req_body, dict) else json.loads(req_body)

        # Validate required fields
        if not all(key in telemetry for key in ["device_id", "temperature"]):
            return func.HttpResponse(
                "Missing required fields: device_id, temperature",
                status_code=400
            )

        # Initialize clients
        _, _, container = initialize_cosmos_client()
        service_bus_client = initialize_service_bus_client()

        # Store telemetry in Cosmos DB
        store_telemetry(container, telemetry)

        # Check for anomalies
        if detect_anomaly(telemetry):
            send_notification(service_bus_client, telemetry)
            return func.HttpResponse(
                json.dumps({"status": "Anomaly detected and notification sent"}),
                status_code=200,
                mimetype="application/json"
            )

        return func.HttpResponse(
            json.dumps({"status": "Telemetry processed successfully"}),
            status_code=200,
            mimetype="application/json"
        )

    except ValueError as ve:
        logger.error(f"Invalid JSON input: {str(ve)}")
        return func.HttpResponse(
            "Invalid JSON input",
            status_code=400
        )
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return func.HttpResponse(
            f"Internal server error: {str(e)}",
            status_code=500
        )
