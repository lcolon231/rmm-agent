// SPDX-License-Identifier: AGPL-3.0-only
package service

import (
	"context"
	"errors"
	"github.com/lcolon231/rmm/agent/internal/chatlaunch"
	"github.com/lcolon231/rmm/agent/internal/chatpipe"
)

var errSupportChat = errors.New("support chat unavailable")

func (a *Agent) serveSupportChat(ctx context.Context, s *session) {
	err := chatpipe.Serve(ctx, func(ctx context.Context, sessionID uint32) error {
		target, err := chatlaunch.ForSession(sessionID)
		if err != nil {
			a.log.Print("support chat: interactive session unavailable")
			return errSupportChat
		}
		defer target.Close()
		return a.openSupportChat(ctx, s.api.OpenSupportChat, target.Open)
	})
	if err != nil && ctx.Err() == nil {
		a.log.Print("support chat: local listener unavailable")
	}
}

func (a *Agent) openSupportChat(ctx context.Context, create func(context.Context) (string, error), open func(string) error) error {
	url, err := create(ctx)
	if err != nil {
		a.log.Print("support chat: server request failed")
		return errSupportChat
	}
	if err := open(url); err != nil {
		a.log.Print("support chat: browser launch failed")
		return errSupportChat
	}
	a.log.Print("support chat: browser launched")
	return nil
}

func (a *Agent) handleChatLaunch(raw string) {
	if raw == "" {
		a.lastChatLaunch = ""
		return
	}
	if raw == a.lastChatLaunch {
		return
	}
	if a.openChatURL == nil {
		a.openChatURL = chatlaunch.Open
	}
	if err := a.openChatURL(raw); err != nil {
		a.log.Print("support chat: heartbeat browser launch failed")
		return
	}
	a.lastChatLaunch = raw
	a.log.Print("support chat: heartbeat browser launched")
}
