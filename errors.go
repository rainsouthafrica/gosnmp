package gosnmp

import (
	"errors"
	"sync/atomic"
)

var (
	ErrReportable       = errors.New("snmp: reportable error")
	ErrUnknownReportPDU = errors.New("snmp: unknown report pdu")
)

// SNMPv3: User-based Security Model stats as per https://tools.ietf.org/html/rfc3414
const (
	usmStatsUnsupportedSecLevels = ".1.3.6.1.6.3.15.1.1.1.0"
	usmStatsNotInTimeWindows     = ".1.3.6.1.6.3.15.1.1.2.0"
	usmStatsUnknownUserNames     = ".1.3.6.1.6.3.15.1.1.3.0"
	usmStatsUnknownEngineIDs     = ".1.3.6.1.6.3.15.1.1.4.0"
	usmStatsWrongDigests         = ".1.3.6.1.6.3.15.1.1.5.0"
	usmStatsDecryptionErrors     = ".1.3.6.1.6.3.15.1.1.6.0"
)

var (
	ErrUnknownSecurityLevel = errors.New("snmp usm: unknown security level")
	ErrNotInTimeWindow      = errors.New("snmp usm: not in time window")
	ErrUnknownUsername      = errors.New("snmp usm: unknown username")
	ErrUnknownEngineID      = errors.New("snmp usm: unknown engine id")
	ErrWrongDigest          = errors.New("snmp usm: wrong digest")
	ErrDecryption           = errors.New("snmp usm: decryption error")
)

type usmStats struct {
	usmStatsUnsupportedSecLevels reportableCounter
	usmStatsNotInTimeWindows     reportableCounter
	usmStatsUnknownUserNames     reportableCounter
	usmStatsUnknownEngineIDs     reportableCounter
	usmStatsWrongDigests         reportableCounter
	usmStatsDecryptionErrors     reportableCounter
}

func newUSMStats() usmStats {
	return usmStats{
		usmStatsUnsupportedSecLevels: reportableCounter{err: ErrUnknownSecurityLevel, oid: usmStatsUnsupportedSecLevels},
		usmStatsNotInTimeWindows:     reportableCounter{err: ErrNotInTimeWindow, oid: usmStatsNotInTimeWindows},
		usmStatsUnknownUserNames:     reportableCounter{err: ErrUnknownUsername, oid: usmStatsUnknownUserNames},
		usmStatsUnknownEngineIDs:     reportableCounter{err: ErrUnknownEngineID, oid: usmStatsUnknownEngineIDs},
		usmStatsWrongDigests:         reportableCounter{err: ErrWrongDigest, oid: usmStatsWrongDigests},
		usmStatsDecryptionErrors:     reportableCounter{err: ErrDecryption, oid: usmStatsDecryptionErrors},
	}
}

// SNMP Message Processing and Dispatching stats, as per https://tools.ietf.org/html/rfc3412
const (
	snmpUnknownSecurityModels = ".1.3.6.1.6.3.11.2.1.1.0"
	snmpInvalidMsgs           = ".1.3.6.1.6.3.11.2.1.2.0"
	snmpUnknownPDUHandlers    = ".1.3.6.1.6.3.11.2.1.3.0"
)

var (
	ErrUnknownSecurityModel = errors.New("snmp mpd: unknown security model")
	ErrInvalidMsg           = errors.New("snmp mpd: invalid message")
	ErrUnknownPDUHandler    = errors.New("snmp mpd: unknown pdu handler")

	ErrUnknownSecurityModels = ErrUnknownSecurityModel // Deprecated: use ErrUnknownSecurityModel
	ErrInvalidMsgs           = ErrInvalidMsg           // Deprecated: use ErrInvalidMsg
	ErrUnknownPDUHandlers    = ErrUnknownPDUHandler    // Deprecated: use ErrUnknownPDUHandler
)

type mpdStats struct {
	snmpUnknownSecurityModels reportableCounter
	snmpInvalidMsgs           reportableCounter
	snmpUnknownPDUHandlers    reportableCounter
}

func newMPDStats() mpdStats {
	return mpdStats{
		snmpUnknownSecurityModels: reportableCounter{err: ErrUnknownSecurityModel, oid: snmpUnknownSecurityModels},
		snmpInvalidMsgs:           reportableCounter{err: ErrInvalidMsg, oid: snmpInvalidMsgs},
		snmpUnknownPDUHandlers:    reportableCounter{err: ErrUnknownPDUHandler, oid: snmpUnknownPDUHandlers},
	}
}

// SNMP Target Objects stats, as per https://tools.ietf.org/html/rfc3413
const (
	snmpUnavailableContexts = ".1.3.6.1.6.3.12.1.4.0"
	snmpUnknownContexts     = ".1.3.6.1.6.3.12.1.5.0"
)

var (
	ErrUnavailableContext = errors.New("snmp: unavailable context")
	ErrUnknownContext     = errors.New("snmp: unknown context")
)

type targetStats struct {
	snmpUnavailableContexts reportableCounter
	snmpUnknownContexts     reportableCounter
}

func newTargetStats() targetStats {
	return targetStats{
		snmpUnavailableContexts: reportableCounter{err: ErrUnavailableContext, oid: snmpUnavailableContexts},
		snmpUnknownContexts:     reportableCounter{err: ErrUnknownContext, oid: snmpUnknownContexts},
	}
}

var reportableErrorsMap = map[string]error{
	usmStatsUnsupportedSecLevels: ErrUnknownSecurityLevel,
	usmStatsNotInTimeWindows:     ErrNotInTimeWindow,
	usmStatsUnknownUserNames:     ErrUnknownUsername,
	usmStatsUnknownEngineIDs:     ErrUnknownEngineID,
	usmStatsWrongDigests:         ErrWrongDigest,
	usmStatsDecryptionErrors:     ErrDecryption,

	snmpUnknownSecurityModels: ErrUnknownSecurityModel,
	snmpInvalidMsgs:           ErrInvalidMsg,
	snmpUnknownPDUHandlers:    ErrUnknownPDUHandler,

	snmpUnavailableContexts: ErrUnavailableContext,
	snmpUnknownContexts:     ErrUnknownContext,
}

func lookupReportableError(pdu SnmpPDU) *reportableError {
	if err, ok := reportableErrorsMap[pdu.Name]; ok {
		v, _ := pdu.Value.(uint32) // TODO: complain somehow when it's not uint32?
		return &reportableError{err: err, oid: pdu.Name, counter: v}
	}
	return &reportableError{err: ErrUnknownReportPDU}
}

type reportableCounter struct {
	err     error
	oid     string
	counter atomic.Uint32
}

func (c *reportableCounter) incErr() error { return &reportableError{c.err, c.oid, c.counter.Add(1)} }
func (c *reportableCounter) get() uint32   { return c.counter.Load() }

// func (c *reportableCounter) addErr(v uint32) error {return &reportableError{c.err, c.oid, c.counter.Add(v)} }

type reportableError struct {
	err     error
	oid     string
	counter uint32
}

func (e *reportableError) Error() string { return e.err.Error() }

func (e *reportableError) Is(target error) bool {
	switch target {
	case ErrReportable, e.err:
		return true
	}
	return false
}

func (e *reportableError) report() SnmpPDU {
	return SnmpPDU{Type: Counter32, Name: e.oid, Value: e.counter}
}
