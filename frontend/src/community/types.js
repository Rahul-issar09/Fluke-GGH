// Shapes of the Community data. These are the contract between the UI and any backend: the mock in
// mockApi.js returns exactly these, and a real API behind VITE_COMMUNITY_API must too.

/**
 * @typedef {Object} User
 * @property {string} id
 * @property {string} name            lower-case, 3-24 chars of a-z 0-9 _
 * @property {string} avatarColor     "#rrggbb"
 * @property {number} reputation      computed: +10 answer upvote, +15 accepted answer, +5 question upvote, +2 post like, -2 per downvote
 * @property {string[]} badges        "First post" | "First answer" | "Helper" | "Bug hunter"
 * @property {string} joinedAt        ISO time
 * @property {boolean} [moderator]    present (true) for moderators only
 *
 * @typedef {Object} FindingRef       a finding shared into a post or question, already redacted
 * @property {string} id
 * @property {string} [scanId]
 * @property {string} category
 * @property {string} owasp
 * @property {"candidate"|"corroborated"|"confirmed"|"resolved"} state
 * @property {string} summary         one line; paths shortened to a basename, hosts replaced with <target>
 *
 * @typedef {Object} Post
 * @property {string} id
 * @property {User} author
 * @property {"text"|"image"|"article"|"code"|"finding"|"repost"} type
 * @property {string} [title]
 * @property {string} body            Markdown
 * @property {string[]} images        data URLs or same-origin paths (png/jpeg/webp only)
 * @property {{lang: string, source: string}} [code]
 * @property {FindingRef} [finding]
 * @property {Post|null} [repostOf]
 * @property {string[]} tags
 * @property {number} likeCount
 * @property {boolean} likedByMe
 * @property {number} commentCount
 * @property {string} createdAt
 * @property {string} [editedAt]
 *
 * @typedef {Object} Comment
 * @property {string} id
 * @property {string} postId
 * @property {string} [parentId]      only top-level comments can be replied to (one reply level)
 * @property {User} author
 * @property {string} body
 * @property {string} createdAt
 *
 * @typedef {Object} Question
 * @property {string} id
 * @property {User} author
 * @property {string} title
 * @property {string} body
 * @property {string[]} tags
 * @property {boolean} beginner
 * @property {number} votes
 * @property {number} myVote          -1, 0 or 1
 * @property {number} answerCount
 * @property {string} [acceptedAnswerId]
 * @property {FindingRef} [finding]
 * @property {string} createdAt
 * @property {Answer[]} [answers]     present on getQuestion()
 *
 * @typedef {Object} Answer
 * @property {string} id
 * @property {string} questionId
 * @property {User} author
 * @property {string} body
 * @property {number} votes
 * @property {number} myVote
 * @property {boolean} accepted
 * @property {string} createdAt
 *
 * @typedef {Object} Resource
 * @property {string} id
 * @property {User} author
 * @property {string} title
 * @property {string} url             https only
 * @property {"tool"|"writeup"|"course"|"cheatsheet"|"video"} kind
 * @property {string[]} tags
 * @property {number} votes
 * @property {boolean} votedByMe
 * @property {string} createdAt
 *
 * @typedef {Object} Job
 * @property {string} id
 * @property {User} author
 * @property {string} role
 * @property {string} company
 * @property {string} location
 * @property {boolean} remote
 * @property {"intern"|"junior"|"mid"|"senior"} level
 * @property {string} url             https only
 * @property {string} postedAt
 * @property {string} expiresAt       expired jobs are not listed
 *
 * @typedef {Object} Notification
 * @property {string} id
 * @property {"like"|"comment"|"answer"|"accepted"|"mention"} kind
 * @property {User} actor
 * @property {string} targetId
 * @property {"post"|"question"} targetType
 * @property {boolean} read
 * @property {string} createdAt
 *
 * @typedef {Object} ReportGroup      every open report on one item, for the moderator queue
 * @property {string} id              the first report's id; resolveReport(id) closes them all
 * @property {"post"|"comment"|"question"|"answer"|"resource"|"job"} kind
 * @property {string} targetId
 * @property {string[]} reasons
 * @property {string[]} reporters     user names
 * @property {number} count
 * @property {string} createdAt       the newest report
 * @property {{exists: boolean, author?: User, excerpt?: string, link?: string}} target
 */

export const REPORT_KINDS = ["post", "comment", "question", "answer", "resource", "job"];

export const POST_TYPES = ["text", "image", "article", "code", "finding", "repost"];
export const CODE_LANGS = ["python", "javascript", "java", "go", "bash"];
export const RESOURCE_KINDS = ["tool", "writeup", "course", "cheatsheet", "video"];
export const JOB_LEVELS = ["intern", "junior", "mid", "senior"];
export const REPORT_REASONS = ["spam", "harassment", "live exploit against a third party", "leaked secret", "other"];
