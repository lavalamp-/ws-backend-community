from rest_framework import status, parsers, renderers
from rest_framework.views import APIView
from rest.serializers.account import ChangePasswordSerialzer
from rest_framework.response import Response
from django.contrib.auth import logout


class AccountChangePasswordView(APIView):
    throttle_classes = ()
    permission_classes = ()
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = ChangePasswordSerialzer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        #Logout the user, to force them to use thier new password
        logout(request)
        return Response(data={}, status=status.HTTP_200_OK)