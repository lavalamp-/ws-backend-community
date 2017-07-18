# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_swagger import renderers

from rest.lib import WebSightSchemaGenerator


class SwaggerSchemaView(APIView):
    """
    This is a view for rendering the API schema as determined by the Django Rest Framework
    Swagger plugin.
    """

    exclude_from_schema = True
    permission_classes = [AllowAny]
    renderer_classes = [
        renderers.OpenAPIRenderer,
        renderers.SwaggerUIRenderer,
    ]

    def get(self, request):
        generator = WebSightSchemaGenerator()
        schema = generator.get_schema(request=request)
        return Response(schema)
