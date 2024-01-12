from rest_framework import exceptions, serializers

from ...rewards.models import CompletedActions, RewardActions, RewardRequests

class CompletedActionsSerializers(serializers.ModelSerializer):
    completed_all_tasks = serializers.SerializerMethodField()

    def get_completed_all_tasks(self, obj) -> bool:
        """
        Get the value of is_reward_open for the serialized object.
        """
        return obj.completed_all_tasks

    class Meta:
        model = CompletedActions
        fields = ['id', 'user', 'tasks', 'completed_all_tasks', 'modified']
        read_only_fields = ['id', 'user', 'tasks', 'modified']

class RewardActionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = RewardActions
        fields = ['id', "reward", 'action', 'platform']
        read_only_fields = ['reward']
        # extra_kwargs = {"url": {"view_name": "api:rewardtask-detail", "lookup_field": "id"}}


class RewardRequestsSerializer(serializers.ModelSerializer):
    completed_tasks = CompletedActionsSerializers(many=False, read_only=True)
    actions = RewardActionsSerializer(many=True, read_only=True)
    is_reward_open = serializers.SerializerMethodField()


    def get_is_reward_open(self, obj) -> bool:
        """
        Get the value of is_reward_open for the serialized object.
        """
        return obj.is_reward_open

    class Meta:
        model = RewardRequests
        fields = [
            "id",
            "is_reward_open",
            "title",
            "image",
            "active",
            "description",
            "subscribers",
            'completed_tasks',
            "max_users",
            "paying",
            "expiry",
            "fb_share_url",
            "fb_like_url",
            "fb_comment_url",
            "fb_follow_url",
            "fb_post_id",
            "ig_artist_username",
            "ig_artist_id",
            "ig_post_id",
            "spotify_artist_id",
            "spotify_playlist_id",
            "spotify_album_id",
            "spotify_track_id",
            "youtube_channel_id",
            "actions",
            "url"
        ]
        read_only_fields = ['active', 'is_reward_open']
        extra_kwargs = {"url": {"view_name": "api:reward-detail", "lookup_field": "pk"}}

    def to_representation(self, instance):
        # Override to filter actions for the specific request
        representation = super().to_representation(instance)
        filtered_actions = instance.actions.filter(reward=instance)
        filtered_completed_actions = instance.completed_actions.filter(tasks=instance)
        representation['completed_tasks'] = CompletedActionsSerializers(filtered_completed_actions, many=True).data
        representation['actions'] = RewardActionsSerializer(filtered_actions, many=True).data
        return representation
