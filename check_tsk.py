import pytsk3

try:
    print(f"TSK Version: {pytsk3.TSK_VERSION_STR}")
    # Try to see if EWF is a supported type
    # pytsk3.TSK_IMG_TYPE_ENUM has attributes
    supported_types = []
    for attr in dir(pytsk3):
        if attr.startswith("TSK_IMG_TYPE_"):
            supported_types.append(attr)
    print(f"Supported Image Types: {supported_types}")
except Exception as e:
    print(f"Error checking TSK info: {e}")
