class InvalidDataTypeError(Exception):
    def __init__(self, data_type):
        self.data_type = data_type
        super().__init__(f"Invalid data_type: {data_type}")