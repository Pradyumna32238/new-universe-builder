from supabase_client import get_supabase_client
from models import User, Universe, Character, UniverseCollaboratorRequest, Issue, Notification, NotificationSettings
from flask import current_app as app

supabase = get_supabase_client()

def get_user_by_id(user_id):
    response = supabase.table('user').select('*').eq('id', user_id).execute()
    if response.data:
        return User(**response.data[0])
    return None

def get_user_by_username(username):
    response = supabase.table('user').select('*').eq('username', username).execute()
    if response.data:
        return User(**response.data[0])
    return None

def get_user_by_email(email):
    response = supabase.table('user').select('*').eq('email', email).execute()
    if response.data:
        return User(**response.data[0])
    return None

def search(query):
    try:
        universe_response = supabase.table('universe').select('*').ilike('title', f'%{query}%').execute()
        character_response = supabase.table('character').select('*, universe(title)').ilike('name', f'%{query}%').execute()
        
        universes = universe_response.data if universe_response.data else []
        characters = character_response.data if character_response.data else []
        
        return universes, characters
    except Exception as e:
        print(f"Error during search: {e}")
        return [], []

def delete_character(character_id):
    """Delete a character by its ID."""
    try:
        response = supabase.table("character").delete().eq("id", character_id).execute()
        return response
    except Exception as e:
        print(f"Error deleting character: {e}")
        return None

def delete_notifications(user_id):
    """Delete all notifications for a user."""
    try:
        supabase.table("notification").delete().eq("user_id", user_id).execute()
    except Exception as e:
        print(f"Error deleting notifications: {e}")
        return None

def create_notification(user_id, message):
    """Create a notification for a user."""
    try:
        supabase.table("notification").insert({"user_id": user_id, "message": message}).execute()
        
        # Get all notifications for the user, ordered by timestamp
        notifications_response = supabase.table("notification").select("id").eq("user_id", user_id).order("timestamp", desc=True).execute()
        
        if len(notifications_response.data) > 5:
            # Get the IDs of the notifications to delete
            notification_ids_to_delete = [n['id'] for n in notifications_response.data[5:]]
            
            # Delete the oldest notifications
            supabase.table("notification").delete().in_("id", notification_ids_to_delete).execute()
            
    except Exception as e:
        print(f"Error creating notification: {e}")
        return None

def get_notification_by_message(user_id, message):
    """Get a notification by its message."""
    try:
        return supabase.table("notification").select("*").eq("user_id", user_id).eq("message", message).execute().data
    except Exception as e:
        print(f"Error getting notification by message: {e}")
        return None

def get_notification_settings(user_id):
    """Get notification settings for a user."""
    try:
        return supabase.table("notification_settings").select("*").eq("user_id", user_id).execute().data
    except Exception as e:
        print(f"Error getting notification settings: {e}")
        return None

def create_notification_settings(user_id, email_notifications):
    """Create notification settings for a user."""
    try:
        supabase.table("notification_settings").insert({"user_id": user_id, "email_notifications": email_notifications}).execute()
    except Exception as e:
        print(f"Error creating notification settings: {e}")
        return None

def update_notification_settings(user_id, email_notifications):
    """Update notification settings for a user."""
    try:
        supabase.table("notification_settings").update({"email_notifications": email_notifications}).eq("user_id", user_id).execute()
    except Exception as e:
        print(f"Error updating notification settings: {e}")
        return None

def create_issue(user_id, title, description, issue_type):
    """Create an issue."""
    try:
        supabase.table("issue").insert({"user_id": user_id, "title": title, "description": description, "issue_type": issue_type}).execute()
    except Exception as e:
        print(f"Error creating issue: {e}")
        return None

def delete_issue(issue_id):
    """Delete an issue by its ID."""
    try:
        response = supabase.table('issue').delete().eq('id', issue_id).execute()
        return response.data
    except Exception as e:
        print(f"Error deleting issue: {e}")
        return None

def update_character(character_id, name, description):
    response = supabase.table('character').update({
        'name': name,
        'description': description
    }).eq('id', character_id).execute()
    return response.data[0] if response.data else None

def create_character(name, description, universe_id, creator_id):
    response = supabase.table('character').insert({
        'name': name,
        'description': description,
        'universe_id': universe_id,
        'creator_id': creator_id
    }).execute()
    return response.data[0] if response.data else None

def get_character_by_id(character_id):
    response = supabase.table('character').select('*, universe:universe_id(*)').eq('id', character_id).single().execute()
    return response.data

def delete_universe(universe_id):
    try:
        response = supabase.table('universe').delete().eq('id', universe_id).execute()
        return response.data
    except Exception as e:
        print(f"Error deleting universe: {e}")
        return None

def update_universe(universe_id, title, description):
    response = supabase.table('universe').update({
        'title': title,
        'description': description
    }).eq('id', universe_id).execute()
    return response.data[0] if response.data else None

def create_universe(title, description, owner_id):
    response = supabase.table('universe').insert({
        'title': title,
        'description': description,
        'owner_id': owner_id
    }).execute()
    return response.data[0] if response.data else None

def get_characters_by_universe_id(universe_id):
    """Fetch all characters for a given universe."""
    try:
        return supabase.table("character").select("*").eq("universe_id", universe_id).execute().data
    except Exception as e:
        print(f"Error fetching characters by universe id: {e}")
        return []

def search_characters(universe_id, search_query):
    """Search for characters in a universe by name."""
    try:
        return supabase.table("character").select("*").eq("universe_id", universe_id).ilike("name", f"%{search_query}%").execute().data
    except Exception as e:
        print(f"Error searching characters: {e}")
        return []

def get_collaboration_requests_by_universe(universe_id):
    """Get all collaboration requests for a given universe."""
    try:
        return supabase.table("universe_collaborator_request").select("*").eq("universe_id", universe_id).eq("status", "pending").execute().data
    except Exception as e:
        print(f"Error getting collaboration requests: {e}")
        return []

def get_collaboration_requests_by_user(universe_id, user_id):
    """Get all collaboration requests for a given universe and user."""
    try:
        return supabase.table("universe_collaborator_request").select("*").eq("universe_id", universe_id).eq("requester_id", user_id).execute().data
    except Exception as e:
        print(f"Error getting collaboration requests: {e}")
        return []

def get_pending_collaboration_request(universe_id, user_id, character_name):
    """Get a pending collaboration request."""
    try:
        return supabase.table("universe_collaborator_request").select("*").eq("universe_id", universe_id).eq("requester_id", user_id).eq("character_name", character_name).eq("status", "pending").execute().data
    except Exception as e:
        print(f"Error getting pending collaboration request: {e}")
        return None

def create_collaboration_request(universe_id, user_id, character_name, character_description):
    """Create a collaboration request."""
    try:
        return supabase.table("universe_collaborator_request").insert({"universe_id": universe_id, "requester_id": user_id, "character_name": character_name, "character_description": character_description}).execute().data
    except Exception as e:
        print(f"Error creating collaboration request: {e}")
        return None

def get_collaboration_request_by_id(request_id):
    """Get a collaboration request by its ID."""
    try:
        return supabase.table("universe_collaborator_request").select("*").eq("id", request_id).single().execute().data
    except Exception as e:
        print(f"Error getting collaboration request by id: {e}")
        return None

def get_all_universes(page=1, per_page=10, search_query=None):
    """Fetch all universes with pagination and search."""
    try:
        query = supabase.table("universe").select("*, owner:owner_id(*), characters:character(*)", count='exact')

        if search_query:
            query = query.ilike('title', f'%{search_query}%')

        start = (page - 1) * per_page
        end = start + per_page - 1

        response = query.order('created_at', desc=True).range(start, end).execute()
        
        universes = []
        for data in response.data:
            owner_data = data.pop('owner')
            characters_data = data.pop('characters')
            universe = Universe(**data)
            if owner_data:
                universe.owner = User(**owner_data)
            if characters_data:
                universe.characters = [Character(**char) for char in characters_data]
            universes.append(universe)
            
        return universes, response.count
    except Exception as e:
        print(f"Error fetching all universes: {e}")
        return [], 0

def get_all_characters():
    """Fetch all characters."""
    try:
        response = supabase.table('character').select('*').execute()
        return response.data
    except Exception as e:
        print(f"Error fetching all characters: {e}")
        return []

def get_all_issues(page=1, per_page=10, search_query=None):
    """Fetch all issues with pagination and search."""
    try:
        query = supabase.table("issue").select("*, user:user_id(*)", count='exact')

        if search_query:
            query = query.ilike('title', f'%{search_query}%')

        start = (page - 1) * per_page
        end = start + per_page - 1

        response = query.order('created_at', desc=True).range(start, end).execute()
        
        issues = []
        for data in response.data:
            user_data = data.pop('user')
            issue = Issue(**data)
            if user_data:
                issue.user = User(**user_data)
            issues.append(issue)
            
        return issues, response.count
    except Exception as e:
        print(f"Error fetching all issues: {e}")
        return [], 0

def get_notifications_by_user(user_id):
    """Get all notifications for a user, ordered by timestamp."""
    try:
        response = supabase.table('notification').select('*').eq('user_id', user_id).order('timestamp', desc=True).execute()
        return response.data
    except Exception as e:
        print(f"Error fetching notifications: {e}")
        return []

def mark_all_notifications_as_read(user_id):
    """Mark all notifications for a user as read."""
    try:
        response = supabase.table('notification').update({'read': True}).eq('user_id', user_id).execute()
        return response.data
    except Exception as e:
        print(f"Error marking notifications as read: {e}")
        return None

def update_collaboration_request_status(request_id, status):
    """Update the status of a collaboration request."""
    try:
        return supabase.table("universe_collaborator_request").update({"status": status}).eq("id", request_id).execute().data
    except Exception as e:
        print(f"Error updating collaboration request status: {e}")
        return None

def get_universe_by_id(universe_id):
    response = supabase.table('universe').select('*').eq('id', universe_id).single().execute()
    return response.data

def search_universes(search_query):
    """Search for universes by title."""
    try:
        return supabase.table("universe").select("*").ilike("title", f"%{search_query}%").execute().data
    except Exception as e:
        print(f"Error searching universes: {e}")
        return []

def get_all_users(page=1, per_page=10, search_query=None):
    """Fetch all users with pagination and search."""
    try:
        query = supabase.table("user").select("*", count='exact')

        if search_query:
            query = query.ilike('username', f'%{search_query}%')

        start = (page - 1) * per_page
        end = start + per_page - 1

        response = query.order('id', desc=True).range(start, end).execute()
        
        users = [User(**data) for data in response.data]
        return users, response.count
    except Exception as e:
        print(f"Error fetching all users: {e}")
        return [], 0

def add_user(user):
    user_dict = {
        'username': user.username,
        'email': user.email,
        'password_hash': user.password_hash,
        'is_admin': user.is_admin,
        'is_verified': user.is_verified,
        'email_verified': user.email_verified,
        'profile_picture_data': user.profile_picture_data,
    }
    response = supabase.table('user').insert(user_dict).execute()
    return response

def update_user(user_id, data):
    """Update a user's data."""
    try:
        response = supabase.table("user").update(data).eq("id", user_id).execute()
        return response
    except Exception as e:
        print(f"Error updating user: {e}")
        return None

def create_bucket_if_not_exists(bucket_name):
    try:
        supabase.storage.get_bucket(bucket_name)
    except Exception:
        supabase.storage.create_bucket(bucket_name)

def delete_user(user_id):
    response = supabase.table('users').delete().eq('id', user_id).execute()
    return response