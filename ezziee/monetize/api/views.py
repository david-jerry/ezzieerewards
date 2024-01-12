from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _

from rest_framework.mixins import (
    ListModelMixin,
    RetrieveModelMixin,
    UpdateModelMixin,
)
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.viewsets import GenericViewSet
from rest_framework.throttling import UserRateThrottle
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response

from ...utils.exceptions import ObjectNotFoundException, UnAuthenticatedUserOrExistsException, UnauthorizedException, UnauthorizedObjectException
from ...utils.logger import LOGGER

from ...utils.pagination import CustomPagination

from .serializers import (
    BanksSerializer,
    UserBankAccountSerializer
)
from ..models import Banks, UserBankAccount

User = get_user_model()

class BaseGenericViewSet(RetrieveModelMixin, ListModelMixin, GenericViewSet):
    """
    Base class for generic viewsets to handle serializers and queryset based on the presence of related settings.
    """

    pagination_class = CustomPagination
    throttle_classes = [UserRateThrottle]


class BanksViewSet(BaseGenericViewSet):
    """
    GenericViewSet for Banks model.
    """

    queryset = Banks.objects.all()
    serializer_class = BanksSerializer
    lookup_field = "slug"
    permission_classes = [AllowAny]


class UserBankAccountViewSet(UpdateModelMixin, RetrieveModelMixin, ListModelMixin, GenericViewSet):
    """
    GenericViewSet for UserBankAccount model.
    """

    pagination_class = CustomPagination
    throttle_classes = [UserRateThrottle]
    serializer_class = UserBankAccountSerializer
    lookup_field = "id"
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if self.request.user.is_authenticated:
            try:
                return [UserBankAccount.objects.get(user=self.request.user)] if not self.request.user.is_staff else UserBankAccount.objects.all()
            except UserBankAccount.DoesNotExist:
                raise ObjectNotFoundException
            except:
                raise UnauthorizedException
        else:
            raise UnAuthenticatedUserOrExistsException

    def get_object(self):
        try:
            if UserBankAccount.objects.filter(user=self.request.user, id=self.kwargs["id"]).exists():
                return UserBankAccount.objects.get(user=self.request.user, pk=self.kwargs["id"])
            elif UserBankAccount.objects.filter(id=self.kwargs["id"]).exists():
                raise UnauthorizedObjectException
        except UserBankAccount.DoesNotExist:
            raise ObjectNotFoundException


    @action(detail=False, methods=['get'])
    def me(self, request):
        try:
            user_bank_account, created = UserBankAccount.objects.get_or_create(user=request.user)

            if created:
                # Handle the case where the object was just created
                # (e.g., initialize some fields, if needed)
                pass

            serializer = UserBankAccountSerializer(user_bank_account, context={"request": request})
            return Response(
                status=status.HTTP_200_OK, data=serializer.data
            )
        except UserBankAccount.DoesNotExist:
            raise ObjectNotFoundException
        except:
            raise UnAuthenticatedUserOrExistsException
