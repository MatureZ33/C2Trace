from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .models import EpisodeTemplate, SourceRoot, SplitName, SplitPolicy


def assign_episode_splits(
    roots: Iterable[SourceRoot],
    episodes: Iterable[EpisodeTemplate],
    *,
    development_root_ids: Iterable[str],
    seen_state_episode_ids: Iterable[str],
    policy: SplitPolicy = SplitPolicy(),
) -> dict[str, SplitName]:
    admitted = {root.root_id: root for root in roots if root.status.value == "admitted"}
    rows = list(episodes)
    episode_by_id = {episode.episode_id: episode for episode in rows}
    if len(episode_by_id) != len(rows):
        raise ValueError("episode IDs are not unique")

    development = tuple(dict.fromkeys(development_root_ids))
    if len(development) != policy.development_roots:
        raise ValueError(f"development split requires {policy.development_roots} roots")
    missing_development = sorted(set(development) - set(admitted))
    if missing_development:
        raise ValueError(
            "development split references roots that are not admitted: "
            + ", ".join(missing_development)
        )

    unseen_roots = sorted(set(admitted) - set(development))
    if len(unseen_roots) < policy.minimum_unseen_root_tool_roots:
        raise ValueError(
            f"unseen-root/tool split requires at least {policy.minimum_unseen_root_tool_roots} roots"
        )

    seen_episode_ids = set(seen_state_episode_ids)
    missing_seen = sorted(seen_episode_ids - set(episode_by_id))
    if missing_seen:
        raise ValueError("seen-state split references unknown episodes: " + ", ".join(missing_seen))
    wrong_root = sorted(
        episode_id
        for episode_id in seen_episode_ids
        if episode_by_id[episode_id].root_id not in development
    )
    if wrong_root:
        raise ValueError(
            "seen-root/unseen-state episodes must belong to development roots: "
            + ", ".join(wrong_root)
        )

    by_development_root: dict[str, list[EpisodeTemplate]] = defaultdict(list)
    for episode in rows:
        if episode.root_id in development:
            by_development_root[episode.root_id].append(episode)
    for root_id in development:
        root_episodes = by_development_root[root_id]
        if not root_episodes:
            raise ValueError(f"development root has no episodes: {root_id}")
        held_out = [episode for episode in root_episodes if episode.episode_id in seen_episode_ids]
        tuning = [episode for episode in root_episodes if episode.episode_id not in seen_episode_ids]
        if not held_out or not tuning:
            raise ValueError(
                f"development root {root_id} requires both development and held-out state episodes"
            )

    development_families = {admitted[root_id].tool_family for root_id in development}
    leaked = sorted(
        {
            admitted[root_id].tool_family
            for root_id in unseen_roots
            if admitted[root_id].tool_family in development_families
        }
    )
    if leaked:
        raise ValueError("unseen tool families leak into development roots: " + ", ".join(leaked))

    result: dict[str, SplitName] = {}
    for episode in rows:
        if episode.root_id not in admitted:
            raise ValueError(f"episode references root that is not admitted: {episode.root_id}")
        if episode.root_id in development:
            result[episode.episode_id] = (
                SplitName.SEEN_ROOT_UNSEEN_STATE
                if episode.episode_id in seen_episode_ids
                else SplitName.DEVELOPMENT
            )
        else:
            result[episode.episode_id] = SplitName.UNSEEN_ROOT_TOOL
    return result


def assign_root_splits(*args, **kwargs):
    raise TypeError(
        "root-level split assignment was removed: use assign_episode_splits so "
        "development roots can hold out unseen-state Episodes"
    )

