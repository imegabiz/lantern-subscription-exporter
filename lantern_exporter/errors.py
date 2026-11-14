class ExporterError(Exception):
    pass


class ApiError(ExporterError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class ExtractionError(ExporterError):
    pass


class ValidationError(ExporterError):
    pass


class OutputError(ExporterError):
    pass
