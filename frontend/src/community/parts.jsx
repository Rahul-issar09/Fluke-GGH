import React from "react";

// "demo_ana" -> "AN"
export const initials = (name) => (String(name).split("_").pop() || String(name)).slice(0, 2).toUpperCase();

export function Avatar({ user, size = 32 }) {
  return (
    <span className="cm-avatar" style={{ "--s": `${size}px`, background: user.avatarColor }} aria-hidden="true">
      {initials(user.name)}
    </span>
  );
}

export function timeAgo(iso) {
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  if (s < 86400 * 30) return `${Math.floor(s / 86400)} d ago`;
  return new Date(iso).toLocaleDateString();
}
