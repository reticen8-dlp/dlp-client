import time
from winrt.windows.ui.notifications import ToastNotificationManager, ToastNotification
from winrt.windows.data.xml.dom import XmlDocument

def show_notification(title, message):
    # Define the App User Model ID (AUMID) for your application
    app_id = "Reticen8-DLP"

    # Create the XML payload for the notification
    toast_xml = f"""
    <toast activationType="protocol">
        <visual>
            <binding template="ToastGeneric">
                <text>{title}</text>
                <text>{message}</text>
            </binding>
        </visual>
    </toast>
    """

    # Convert the XML string to an XML document
    toast_doc = XmlDocument()
    toast_doc.load_xml(toast_xml)

    # Create a toast notification and show it
    notifier = ToastNotificationManager.create_toast_notifier(app_id)
    toast = ToastNotification(toast_doc)
    notifier.show(toast)

    # Delay to ensure the notification is shown before script exits
    time.sleep(2)

# # Example Usage
# if __name__ == "__main__":
#     show_notification("Security Alert", "Sensitive data detected in clipboard!")
