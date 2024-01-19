from django.db.models.query import QuerySet
import requests

from pprint import pprint

from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.mixins import (
    ListModelMixin,
    RetrieveModelMixin,
    UpdateModelMixin,
    CreateModelMixin,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import GenericViewSet
from rest_framework.throttling import UserRateThrottle
from rest_framework.response import Response
from rest_framework.views import APIView

from ezziee.users.api.serializers import UserSerializer

from ...utils.spotify_link_extractor import spotify_encode_to_base64
from ...utils.exceptions import UnAuthenticatedUserOrExistsException
from ...utils.logger import LOGGER
from ...utils.pagination import CustomPagination

from .serializers import (
    RewardActionsSerializer,
    RewardRequestsSerializer,
)
from ..models import CompletedActions, RewardActions, RewardRequests

User = get_user_model()


class BaseGenericViewSet(RetrieveModelMixin, ListModelMixin, GenericViewSet):
    """
    Base class for generic viewsets to handle serializers and queryset based on the presence of related settings.
    """

    pagination_class = CustomPagination
    throttle_classes = [UserRateThrottle]


class RewardViewset(CreateModelMixin, BaseGenericViewSet):
    queryset = RewardRequests.objects.all()
    serializer_class = RewardRequestsSerializer
    lookup_field = "pk"
    permission_classes = [IsAuthenticated]

    def get_queryset(self) -> QuerySet:
        if not self.request.user.is_staff:
            qs = RewardRequests.objects.filter(active=True)
        else:
            qs = self.queryset
        return qs

    def get_serializer_class(self):
        if self.action == 'create_action':
            return RewardActionsSerializer
        return RewardRequestsSerializer

    @action(detail=True, methods=["post"], url_path="actions/add-action")
    def create_action(self, request, pk=None):
        try:
            task = self.get_object()

            action_serializer = RewardActionsSerializer(data=request.data)
            action_serializer.is_valid(raise_exception=True)
            action_serializer.save(reward=task)

            task_serializer = RewardRequestsSerializer(task, context={'request': request})
            return Response(status=status.HTTP_201_CREATED, data={"detail": _("Action added successfully"), 'task': task_serializer.data})
        except Exception:
            raise UnAuthenticatedUserOrExistsException


class RewardActionsViewset(UpdateModelMixin, BaseGenericViewSet):
    serializer_class = RewardActionsSerializer
    queryset = RewardActions.objects.all()
    lookup_field = "id"
    permission_classes = [IsAuthenticated]

    # instagram
    @action(detail=True, methods=["get"])
    def instagram_like_post(self, request, id=None):
        try:
            action = self.get_object()
            LOGGER.info(f"INSTAGRAM POST ID: {action.reward.ig_post_id}")
            LOGGER.info(f"INSTAGRAM USERID: {request.user.instagram_id}")

            artist_post = action.reward.ig_post_id

            if artist_post is not "" and request.user.instagram_id is not (None or ""):
                url = "https://instagram-manage-api.p.rapidapi.com/postLike"

                payload = {"media_id": artist_post}
                headers = {
                    "content-type": "application/json",
                    "Authorization": request.user.instagram_id,
                    "X-RapidAPI-Key": settings.RAPIDAPI_KEY,
                    "X-RapidAPI-Host": "instagram-manage-api.p.rapidapi.com",
                }

                response = requests.post(url, json=payload, headers=headers)

                res = response.json()
                LOGGER.info(pprint(res))
                LOGGER.info(res['message'])

                if res['status'] == 'success':
                    complted_task = CompletedActions.objects.get_or_create(user=request.user, defaults={'task':action.reward, 'user':request.user, 'point':1})
                    complted_task.point += 1
                    complted_task.save()
                    if complted_task.completed_all_tasks:
                        action.reward.subscribers.add(request.user)
                    return Response(
                        status=status.HTTP_200_OK, data={"detail": _("Instagram Post ID LIKED")}
                    )
                elif res['error'] == 'Invalid token':
                    return Response(
                        status=status.HTTP_400_BAD_REQUEST, data={"detail": _("Invalid API Token")}
                    )
                elif "You have exceeded the DAILY quota for Requests on your current" in res['message']:
                    return Response(
                        status=status.HTTP_400_BAD_REQUEST, data={'detail': res['message']}
                    )
            else:
                return Response(
                    status=status.HTTP_400_BAD_REQUEST, data={"detail": _("Instagram Post ID unavailable")}
                )
        except:
            raise UnAuthenticatedUserOrExistsException

    @action(detail=True, methods=["get"])
    def instagram_follow_artist(self, request, id=None):
        """Once this action to follow an artist on IG, the function executes
        a follow request to the endpoint to follow the user, when successful
        returns the status of that request proving the request was successful

        Args:
            request (_type_): _description_

        Raises:
            UnAuthenticatedUserOrExistsException: I fth euser is not authenticated
            they would be thrown an exception stating they were not authenticated

        Returns:
            _type_: status of the follow request, be it successful or not successful
        """
        try:
            # Assuming the token is provided in the request data as 'facebook_token'
            action = self.get_object()
            LOGGER.info(action.reward)

            artist_to_follow = action.reward.ig_artist_id

            if artist_to_follow and request.user.instagram_id:
                url = "https://instagram-manage-api.p.rapidapi.com/followUser"

                payload = {"user_id": action.reward.ig_artist_id}
                headers = {
                    "content-type": "application/json",
                    "Authorization": request.user.instagram_id,
                    "X-RapidAPI-Key": settings.RAPIDAPI_KEY,
                    "X-RapidAPI-Host": "instagram-manage-api.p.rapidapi.com",
                }

                response = requests.post(url, json=payload, headers=headers)
                res = response.json()

                LOGGER.info(pprint(res))
                if res['status'] == 'success':
                    complted_task = CompletedActions.objects.get_or_create(user=request.user, defaults={'task':action.reward, 'user':request.user, 'point':1})
                    complted_task.point += 1
                    complted_task.save()
                    if complted_task.completed_all_tasks:
                        action.reward.subscribers.add(request.user)
                    serializer = UserSerializer(request.user, context={"request": request})
                    return Response(
                        status=status.HTTP_200_OK, data={"detail": _("Instagram account followed"), "userData": serializer.data}
                    )
                elif res['error'] == 'Invalid token':
                    return Response(
                        status=status.HTTP_400_BAD_REQUEST, data={"detail": _("Invalid API Token")}
                    )
                return Response(
                    status=status.HTTP_200_OK, data={"detail": _("Failure performing a followe on instagram"), "userData": serializer.data}
                )

            else:
                return Response(
                    status=status.HTTP_400_BAD_REQUEST, data={"detail": _("Instagram Authentication Failed")}
                )
        except:
            raise UnAuthenticatedUserOrExistsException

    # spotify
    @action(detail=True, methods=["get"])
    def spotify_follow_artist(self, request, id=None):
        try:
            action = self.get_object()

            artist_id = action.reward.spotify_artist_id

            if not artist_id == "":
                url = "https://api.spotify.com/v1/me/following"
                authorization = spotify_encode_to_base64()

                payload = {"type": "artist", "id": artist_id}
                headers = {
                    "content-type": "application/json",
                    "Authorization": f"Basic {authorization}",
                }

                response = requests.put(url, json=payload, headers=headers)

                res = response.json()

                LOGGER.info(pprint(res))
                # TODO: Confirm what is returned and then use the information to perform a like
                # TODO: Once the like has been done, add the amount to the persons wallet
            else:
                return Response(
                    status=status.HTTP_400_BAD_REQUEST, data={"detail": _("Instagram Post ID unavailable")}
                )
        except:
            raise UnAuthenticatedUserOrExistsException

    @action(detail=True, methods=["get"])
    def spotify_follow_playlist(self, request, id=None):
        try:
            action = self.get_object()

            playlist_id = action.reward.spotify_playlist_id

            if not playlist_id == "":
                url = f"https://api.spotify.com/v1/playlists/{playlist_id}/followers"
                authorization = spotify_encode_to_base64()

                payload = {"public": True}
                headers = {
                    "content-type": "application/json",
                    "Authorization": f"Basic {authorization}",
                }

                response = requests.put(url, json=payload, headers=headers)

                res = response.json()

                LOGGER.info(pprint(res))
                # TODO: Confirm what is returned and then use the information to perform a like
                # TODO: Once the like has been done, add the amount to the persons wallet
            else:
                return Response(
                    status=status.HTTP_400_BAD_REQUEST, data={"detail": _("Instagram Post ID unavailable")}
                )
        except:
            raise UnAuthenticatedUserOrExistsException

    @action(detail=True, methods=["get"])
    def spotify_save_album(self, request, id=None):
        try:
            action = self.get_object()

            album_id = action.reward.spotify_album_id

            if not album_id == "":
                url = f"https://api.spotify.com/v1/me/albums"
                authorization = spotify_encode_to_base64()

                payload = {"id": album_id}
                headers = {
                    "content-type": "application/json",
                    "Authorization": f"Basic {authorization}",
                }

                response = requests.put(url, json=payload, headers=headers)

                res = response.json()

                LOGGER.info(pprint(res))
                # TODO: Confirm what is returned and then use the information to perform a like
                # TODO: Once the like has been done, add the amount to the persons wallet
            else:
                return Response(
                    status=status.HTTP_400_BAD_REQUEST, data={"detail": _("Instagram Post ID unavailable")}
                )
        except:
            raise UnAuthenticatedUserOrExistsException

    @action(detail=True, methods=["get"])
    def spotify_save_track(self, request, id=None):
        try:
            action = self.get_object()

            track_id = action.reward.spotify_track_id

            if not track_id == "":
                url = f"https://api.spotify.com/v1/me/tracks"
                authorization = spotify_encode_to_base64()

                payload = {"id": track_id}
                headers = {
                    "content-type": "application/json",
                    "Authorization": f"Basic {authorization}",
                }

                response = requests.put(url, json=payload, headers=headers)

                res = response.json()

                LOGGER.info(pprint(res))
                # TODO: Confirm what is returned and then use the information to perform a like
                # TODO: Once the like has been done, add the amount to the persons wallet
            else:
                return Response(
                    status=status.HTTP_400_BAD_REQUEST, data={"detail": _("Instagram Post ID unavailable")}
                )
        except:
            raise UnAuthenticatedUserOrExistsException
