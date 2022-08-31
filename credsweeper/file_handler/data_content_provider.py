import base64
import json
import logging
from typing import List, Optional

import yaml
from lxml import etree

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider

logger = logging.getLogger(__name__)


class DataContentProvider(ContentProvider):
    """Dummy raw provider to keep bytes

    Parameters:
        data: byte sequence to be stored.
        file_path: optional string. Might be specified if you know true file name lines was taken from.

    """

    def __init__(self, data: bytes, file_path: Optional[str] = None, info: Optional[str] = None) -> None:
        super().__init__(file_path if file_path is not None else "", info if info is not None else "")
        self.data = data
        self.structure = None
        self.decoded: Optional[bytes] = None

    @property
    def data(self) -> bytes:
        """data getter"""
        return self.__data

    @data.setter
    def data(self, data: bytes) -> None:
        """data setter"""
        self.__data = data

    def is_structure(self) -> bool:
        try:
            text = self.data.decode(encoding='utf-8', errors='strict')
        except Exception:
            return False
        try:
            self.structure = json.loads(text)
            logger.debug("CONVERTED from json")
            # logger.debug("CONVERTED from '%s' json:\n%s", self.data.decode(encoding='utf-8', errors='strict'),
            #              str(self.structure))
        except Exception as exc:
            logger.debug("Cannot parse as json:%s %s", exc, self.data)
            self.structure = None
        if self.structure is not None:
            return isinstance(self.structure, dict) or isinstance(self.structure, list)
        try:
            self.structure = yaml.load(text, Loader=yaml.FullLoader)
            logger.debug("CONVERTED from yaml")
            # logger.debug("CONVERTED from '%s' yaml:\n%s", self.data.decode(encoding='utf-8', errors='strict'),
            #              str(self.structure))
        except Exception as exc:
            logger.debug("Cannot parse as yaml:%s %s", exc, self.data)
            self.structure = None
        if self.structure is not None:
            return isinstance(self.structure, dict) or isinstance(self.structure, list)
        try:
            xml_tree = etree.fromstring(text)

            def elem2dict(node):
                """
                Convert an lxml.etree node tree into a dict.
                """
                result = {}

                for element in node.iterchildren():
                    key = element.tag.split('}')[1] if '}' in element.tag else element.tag
                    if element.text and element.text.strip():
                        value = element.text
                    else:
                        value = elem2dict(element)
                    if key in result:

                        if type(result[key]) is list:
                            result[key].append(value)
                        else:
                            temp_value = result[key].copy()
                            result[key] = [temp_value, value]
                    else:
                        result[key] = value
                return result

            self.structure = elem2dict(xml_tree)
            logger.debug("CONVERTED from xml")
            # logger.debug("CONVERTED from '%s' xml:\n%s", self.data.decode(encoding='utf-8', errors='strict'),
            #              str(self.structure))
        except Exception as exc:
            logger.debug("Cannot parse as xml:%s %s", exc, self.data)
            self.structure = None
        if self.structure is not None:
            return isinstance(self.structure, dict) or isinstance(self.structure, list)
        return False

    def is_encoded(self) -> bool:
        try:
            self.decoded = base64.b64decode(self.data, validate=True)
        except Exception as exc:
            logger.debug("Cannot decoded as base64:%s %s", exc, self.data)
            return False
        return self.decoded is not None and 0 < len(self.decoded)

    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Return nothing. The class provides only data storage.

        Raise:
            NotImplementedError

        """
        raise NotImplementedError()
