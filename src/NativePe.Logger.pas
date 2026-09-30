{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: MIT

  See LICENSE.
}
unit NativePe.Logger;

interface

type
  TNativePeLogLevel = (llNone, llError, llWarning, llInfo, llDebug);

  TNativePeLogSink = procedure(Level: TNativePeLogLevel; const Msg: string);

procedure NativePeSetLogVerbosity(Level: TNativePeLogLevel);
function NativePeGetLogVerbosity: TNativePeLogLevel;
procedure NativePeSetLogSink(Sink: TNativePeLogSink);

procedure LogError(const Msg: string); overload;
procedure LogError(const Fmt: string; const Args: array of const); overload;
procedure LogWarning(const Msg: string); overload;
procedure LogWarning(const Fmt: string; const Args: array of const); overload;
procedure LogInfo(const Msg: string); overload;
procedure LogInfo(const Fmt: string; const Args: array of const); overload;
procedure LogDebug(const Msg: string); overload;
procedure LogDebug(const Fmt: string; const Args: array of const); overload;

implementation

uses
  Winapi.Windows,
  System.SysUtils;

var
  GVerbosity: TNativePeLogLevel = llError;
  GSink: TNativePeLogSink = nil;

const
  LevelTag: array [TNativePeLogLevel] of string = ('NONE', 'ERROR', 'WARNING', 'INFO', 'DEBUG');

procedure NativePeSetLogVerbosity(Level: TNativePeLogLevel);
begin
  GVerbosity := Level;
end;

function NativePeGetLogVerbosity: TNativePeLogLevel;
begin
  Result := GVerbosity;
end;

procedure NativePeSetLogSink(Sink: TNativePeLogSink);
begin
  GSink := Sink;
end;

procedure DefaultSink(Level: TNativePeLogLevel; const Msg: string);
begin
  OutputDebugString(PChar('[' + LevelTag[Level] + '] ' + Msg));
end;

procedure EmitLog(Level: TNativePeLogLevel; const Msg: string);
begin
  if Ord(GVerbosity) < Ord(Level) then
    Exit;
  if Assigned(GSink) then
    GSink(Level, Msg)
  else
    DefaultSink(Level, Msg);
end;

procedure LogError(const Msg: string);
begin
  EmitLog(llError, Msg);
end;

procedure LogError(const Fmt: string; const Args: array of const);
begin
  EmitLog(llError, Format(Fmt, Args));
end;

procedure LogWarning(const Msg: string);
begin
  EmitLog(llWarning, Msg);
end;

procedure LogWarning(const Fmt: string; const Args: array of const);
begin
  EmitLog(llWarning, Format(Fmt, Args));
end;

procedure LogInfo(const Msg: string);
begin
  EmitLog(llInfo, Msg);
end;

procedure LogInfo(const Fmt: string; const Args: array of const);
begin
  EmitLog(llInfo, Format(Fmt, Args));
end;

procedure LogDebug(const Msg: string);
begin
  EmitLog(llDebug, Msg);
end;

procedure LogDebug(const Fmt: string; const Args: array of const);
begin
  EmitLog(llDebug, Format(Fmt, Args));
end;

end.
