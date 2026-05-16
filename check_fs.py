import pytsk3

supported_fs = []
for attr in dir(pytsk3):
    if attr.startswith("TSK_FS_TYPE_"):
        supported_fs.append(attr)
print(f"Supported Filesystems: {supported_fs}")
