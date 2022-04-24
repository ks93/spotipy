__all__ = [
    'CacheHandler',
    'CacheFileHandler',
    'DjangoSessionCacheHandler',
    'MemoryCacheHandler',
    'RedisCacheHandler']

import errno
import json
import logging
import os
import sqlite3
from typing import final
from spotipy.util import CLIENT_CREDS_ENV_VARS

from redis import RedisError


logger = logging.getLogger(__name__)


class CacheHandler():
    """
    An abstraction layer for handling the caching and retrieval of
    authorization tokens.

    Custom extensions of this class must implement get_cached_token
    and save_token_to_cache methods with the same input and output
    structure as the CacheHandler class.
    """

    def get_cached_token(self):
        """
        Get and return a token_info dictionary object.
        """
        # return token_info
        raise NotImplementedError()

    def save_token_to_cache(self, token_info):
        """
        Save a token_info dictionary object to the cache and return None.
        """
        raise NotImplementedError()
        return None


class CacheFileHandler(CacheHandler):
    """
    Handles reading and writing cached Spotify authorization tokens
    as json files on disk.
    """

    def __init__(self,
                 cache_path=None,
                 username=None):
        """
        Parameters:
             * cache_path: May be supplied, will otherwise be generated
                           (takes precedence over `username`)
             * username: May be supplied or set as environment variable
                         (will set `cache_path` to `.cache-{username}`)
        """

        if cache_path:
            self.cache_path = cache_path
        else:
            cache_path = ".cache"
            username = (username or os.getenv(CLIENT_CREDS_ENV_VARS["client_username"]))
            if username:
                cache_path += "-" + str(username)
            self.cache_path = cache_path

    def get_cached_token(self):
        token_info = None

        try:
            f = open(self.cache_path)
            token_info_string = f.read()
            f.close()
            token_info = json.loads(token_info_string)

        except IOError as error:
            if error.errno == errno.ENOENT:
                logger.debug("cache does not exist at: %s", self.cache_path)
            else:
                logger.warning("Couldn't read cache at: %s", self.cache_path)

        return token_info

    def save_token_to_cache(self, token_info):
        try:
            f = open(self.cache_path, "w")
            f.write(json.dumps(token_info))
            f.close()
        except IOError:
            logger.warning('Couldn\'t write token to cache at: %s',
                           self.cache_path)


class MemoryCacheHandler(CacheHandler):
    """
    A cache handler that simply stores the token info in memory as an
    instance attribute of this class. The token info will be lost when this
    instance is freed.
    """

    def __init__(self, token_info=None):
        """
        Parameters:
            * token_info: The token info to store in memory. Can be None.
        """
        self.token_info = token_info

    def get_cached_token(self):
        return self.token_info

    def save_token_to_cache(self, token_info):
        self.token_info = token_info


class DjangoSessionCacheHandler(CacheHandler):
    """
    A cache handler that stores the token info in the session framework
    provided by Django.

    Read more at https://docs.djangoproject.com/en/3.2/topics/http/sessions/
    """

    def __init__(self, request):
        """
        Parameters:
            * request: HttpRequest object provided by Django for every
            incoming request
        """
        self.request = request

    def get_cached_token(self):
        token_info = None
        try:
            token_info = self.request.session['token_info']
        except KeyError:
            logger.debug("Token not found in the session")

        return token_info

    def save_token_to_cache(self, token_info):
        try:
            self.request.session['token_info'] = token_info
        except Exception as e:
            logger.warning("Error saving token to cache: " + str(e))


class RedisCacheHandler(CacheHandler):
    """
    A cache handler that stores the token info in the Redis.
    """

    def __init__(self, redis, key=None):
        """
        Parameters:
            * redis: Redis object provided by redis-py library
            (https://github.com/redis/redis-py)
            * key: May be supplied, will otherwise be generated
                   (takes precedence over `token_info`)
        """
        self.redis = redis
        self.key = key if key else 'token_info'

    def get_cached_token(self):
        token_info = None
        try:
            token_info = self.redis.get(self.key)
            if token_info:
                return json.loads(token_info)
        except RedisError as e:
            logger.warning('Error getting token from cache: ' + str(e))

        return token_info

    def save_token_to_cache(self, token_info):
        try:
            self.redis.set(self.key, json.dumps(token_info))
        except RedisError as e:
            logger.warning('Error saving token to cache: ' + str(e))


class SQLiteCacheHandler(CacheHandler):
    """
    A cache handler that stores the token info as json in a table `token_info` of a SQLite database.
    Uses the Python built-in `sqlite3`.
    """

    def __init__(self, db_path="cache.db", username=None):
        """
        Parameters:
             * db_path: May be supplied. Defaults to `cache.db`. Will be created
                        if it doesn't exist.
             * username: Unique ID for a specific user. May be supplied or set as
                         environment variable. (Used as the key for the entry,
                         enabling mulitple authenticated users).
        """
        self.db_path = db_path
        self.username = username or os.getenv(CLIENT_CREDS_ENV_VARS["client_username"], "token_info")

        con = sqlite3.connect(self.db_path)
        con.execute(
            "CREATE TABLE IF NOT EXISTS token_info (key TEXT PRIMARY KEY, value TEXT);"
        )
        con.close()

    def get_cached_token(self):
        token_info = None
        try:
            con = sqlite3.connect(self.db_path)
            token_info_json = con.execute(
                "SELECT value FROM token_info WHERE key=?", (self.username,)
            ).fetchone()
            if token_info_json:
                return json.loads(token_info_json[0])
        except sqlite3.Error as error:
            logger.warning('Error getting token from cache: ', error.args[0])
        finally:
            con.close()

        return token_info

    def save_token_to_cache(self, token_info):
        con = sqlite3.connect(self.db_path)
        token_info_json = json.dumps(token_info)
        try:
            con.execute(
                "INSERT INTO token_info VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (self.username, token_info_json),
            )
            con.commit()
        except sqlite3.Error as error:
            logger.warning('Error saving token to cache: ', error.args[0])
        finally:
            con.close()