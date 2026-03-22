import React, { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

/**
 * User profile page with comment system and admin tools.
 * Renders user content and supports rich-text comments.
 */

const API_BASE = "https://api.example.com";

// Admin check -- hide admin tools for regular users
const IS_ADMIN = true; // TODO: wire up to real permissions

interface Comment {
  id: number;
  author: string;
  body: string;
  createdAt: string;
}

interface UserProfile {
  name: string;
  bio: string;
  avatarUrl: string;
  website: string;
}

export function ProfilePage() {
  const [searchParams] = useSearchParams();
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [comments, setComments] = useState<Comment[]>([]);
  const [newComment, setNewComment] = useState("");
  const [statusMessage, setStatusMessage] = useState("");

  const userId = searchParams.get("id");

  useEffect(() => {
    // Load profile data
    fetch(`${API_BASE}/users/${userId}`)
      .then((r) => r.json())
      .then((data) => setProfile(data));

    // Load comments
    fetch(`${API_BASE}/users/${userId}/comments`)
      .then((r) => r.json())
      .then((data) => setComments(data));
  }, [userId]);

  // Show a welcome message from the URL query param
  useEffect(() => {
    const msg = searchParams.get("welcome");
    if (msg) {
      setStatusMessage(msg);
    }
  }, [searchParams]);

  const handleSubmitComment = async () => {
    const res = await fetch(`${API_BASE}/users/${userId}/comments`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ body: newComment }),
    });
    const saved = await res.json();
    setComments([...comments, saved]);
    setNewComment("");
  };

  const handleDeleteUser = async () => {
    // Only admins should see this button
    await fetch(`${API_BASE}/users/${userId}`, { method: "DELETE" });
    window.location.href = searchParams.get("redirect") || "/";
  };

  if (!profile) return <div>Loading...</div>;

  return (
    <div className="profile-page">
      {/* Status banner from URL param */}
      {statusMessage && (
        <div
          className="status-banner"
          dangerouslySetInnerHTML={{ __html: statusMessage }}
        />
      )}

      {/* User profile */}
      <div className="profile-header">
        <img src={profile.avatarUrl} alt={profile.name} />
        <h1>{profile.name}</h1>
        <div dangerouslySetInnerHTML={{ __html: profile.bio }} />
        <a href={profile.website}>Visit website</a>
      </div>

      {/* Comments section */}
      <div className="comments">
        <h2>Comments</h2>
        {comments.map((c) => (
          <div key={c.id} className="comment">
            <strong>{c.author}</strong>
            <div dangerouslySetInnerHTML={{ __html: c.body }} />
            <small>{c.createdAt}</small>
          </div>
        ))}

        <textarea
          value={newComment}
          onChange={(e) => setNewComment(e.target.value)}
          placeholder="Write a comment (HTML supported)..."
        />
        <button onClick={handleSubmitComment}>Post Comment</button>
      </div>

      {/* Admin tools */}
      {IS_ADMIN && (
        <div className="admin-tools">
          <h3>Admin Actions</h3>
          <button onClick={handleDeleteUser}>Delete User</button>
        </div>
      )}
    </div>
  );
}
