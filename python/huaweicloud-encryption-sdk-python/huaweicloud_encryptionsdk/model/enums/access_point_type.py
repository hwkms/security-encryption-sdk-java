from enum import Enum


class AccessPointType(Enum):

    ECS = (1, "ECS")
    CUSTOM = (2, "Custom")
    CCE = (3, "CCE")
    MA = (4, "MA")

    def __init__(self, code, display_name):
        self._code = code
        self._display_name = display_name

    @property
    def code(self):
        return self._code

    @property
    def display_name(self):
        return self._display_name

    @classmethod
    def get_display_name_by_code(cls, code):
        for apt in cls:
            if apt.code == code:
                return apt.display_name
        return "Unknown"
