import React from "react";

// What every Community screen can use:
//   user           the signed-in User, or null
//   requireAuth(fn) runs fn now when signed in; otherwise opens the sign-in box and runs fn after sign-in
//   version        changes whenever data should be reloaded (sign-in, sign-out, reset)
//   reload()       bump version
//   go(path)       opens a Community screen, e.g. go("qa/q-3"), go("post/p-1"), go("u/demo_ana")
export const CommunityContext = React.createContext({ user: null, requireAuth: (fn) => fn(), version: 0, reload: () => {}, go: () => {} });
export const useCommunity = () => React.useContext(CommunityContext);
