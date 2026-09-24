package consensus

import "errors"

// NotifyIngress retries construction only in the protocol manager's existing
// authenticated, ready leader view. It does not change view/epoch/parent, vote,
// unlock a watermark, or create a timeout certificate. The caller owns the actor.
func (a *Application) NotifyIngress() error {
	if err := a.check(); err != nil {
		return err
	}
	if !a.started {
		return errors.New("DEX ingress before consensus start")
	}
	if a.CertifiedHeight() >= a.config.MaxHeight {
		return nil
	}
	if a.manager.CanTryPropose() {
		return a.manager.TryPropose()
	}
	return nil
}
