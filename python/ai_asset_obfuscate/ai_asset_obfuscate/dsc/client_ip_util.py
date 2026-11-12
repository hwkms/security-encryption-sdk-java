#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Client IP utility for detecting ECS instance IP"""

import socket
import requests
from typing import Optional


class ClientIpUtil:
    """Utility class to get client IP address"""

    ECS_METADATA_URL = "http://169.254.169.254/latest/meta-data/public-ipv4"
    ECS_METADATA_TIMEOUT = 1.0  # 1 second timeout

    @staticmethod
    def get_client_ip() -> str:
        """Get client IP address.

        Priority:
        1. ECS metadata (for cloud instances)
        2. Socket connection (fallback)

        Returns:
            str: Client IP address
        """
        # Try ECS metadata first
        # ecs_ip = ClientIpUtil._get_ecs_metadata_ip()
        # if ecs_ip:
        #     return ecs_ip

        # Fallback to socket
        return ClientIpUtil._get_socket_ip()

    @staticmethod
    def _get_ecs_metadata_ip() -> Optional[str]:
        """Get IP from ECS metadata service.

        Returns:
            Optional[str]: IP address if running on ECS, None otherwise
        """
        try:
            response = requests.get(
                ClientIpUtil.ECS_METADATA_URL,
                timeout=ClientIpUtil.ECS_METADATA_TIMEOUT
            )
            if response.status_code == 200:
                ip = response.text.strip()
                if ip:
                    return ip
        except Exception:
            # Not running on ECS or metadata service unavailable
            pass
        return None

    @staticmethod
    def _get_socket_ip() -> str:
        """Get IP address using socket connection.

        Returns:
            str: Local IP address
        """
        try:
            # Create a socket and connect to a public DNS server
            # This doesn't actually send data, just gets the local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                return ip
            finally:
                s.close()
        except Exception:
            # Last resort fallback
            return "127.0.0.1"
