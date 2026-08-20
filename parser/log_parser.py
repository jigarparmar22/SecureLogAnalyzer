from defusedxml import ElementTree as DET

NAMESPACE = {
    "ns": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def parse_xml_log(filepath):
    """
    Parse a Windows Event XML log file into a list of event dictionaries.

    Uses defusedxml to safely parse untrusted XML, preventing
    XXE / entity-expansion attacks. Raises ValueError on malformed
    or unsafe XML so callers can surface a friendly error.
    """
    try:
        tree = DET.parse(filepath)
    except Exception as error:
        raise ValueError(
            "The uploaded file is not a valid or safe XML document."
        ) from error

    root = tree.getroot()

    events = []

    for event in root.findall("ns:Event", NAMESPACE):

        system = event.find("ns:System", NAMESPACE)
        rendering = event.find("ns:RenderingInfo", NAMESPACE)

        if system is None:
            continue

        provider = system.find("ns:Provider", NAMESPACE)
        event_id = system.find("ns:EventID", NAMESPACE)
        level = system.find("ns:Level", NAMESPACE)
        computer = system.find("ns:Computer", NAMESPACE)
        time_created = system.find("ns:TimeCreated", NAMESPACE)

        level_name = "Unknown"
        message = ""

        if rendering is not None:
            level_element = rendering.find("ns:Level", NAMESPACE)
            message_element = rendering.find("ns:Message", NAMESPACE)

            if level_element is not None:
                level_name = level_element.text

            if message_element is not None:
                message = message_element.text.strip()

        event_info = {
            "event_id": event_id.text if event_id is not None else "N/A",
            "provider": provider.get("Name") if provider is not None else "N/A",
            "level": level_name,
            "computer": computer.text if computer is not None else "N/A",
            "time": time_created.get("SystemTime") if time_created is not None else "N/A",
            "message": message
        }

        events.append(event_info)

    return events