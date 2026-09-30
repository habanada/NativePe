# NativePe Real-World Tests

The real-world tests use small compiled programs to check NativePe against running Windows processes and manually loaded PE files.

## Process dump test

This is the simplest controlled process dump test.

### 1. Start the target

For a 64-bit Release build:

```text
bin\Win64\Release\RealWorld\NativePeProcessDumpTarget.exe
```

The target prints its process ID and architecture:

```text
PID=1234
BITS=64
COM=0
```

Keep this window open.

### 2. Copy the PID

Use the value printed after `PID=`.

Example:

```text
1234
```

### 3. Dump the process

Open another command prompt and run:

```text
bin\Win64\Release\Tools\NativePeProcessDump.exe --pid 1234 --out NativePeProcessDumpTarget-dump.exe --verbose
```

Replace `1234` with the PID printed by the target.

The target must still be running while the dump is created.

### 4. Verify the dump

Run:

```text
bin\Win64\Release\RealWorld\NativePeRealWorldRunner.exe verify-dump NativePeProcessDumpTarget-dump.exe 64
```

A successful verification ends with:

```text
RESULT: PASS - dumped PE parsed and core directories validated
```

### 5. Close the target

After the dump and verification are complete, close the `NativePeProcessDumpTarget.exe` window or terminate the process.

## Win32

For a 32-bit test, use the Win32 executables instead:

```text
bin\Win32\Release\RealWorld\NativePeProcessDumpTarget.exe
bin\Win32\Release\Tools\NativePeProcessDump.exe
bin\Win32\Release\RealWorld\NativePeRealWorldRunner.exe
```

Pass `32` to `verify-dump`:

```text
bin\Win32\Release\RealWorld\NativePeRealWorldRunner.exe verify-dump NativePeProcessDumpTarget-dump.exe 32
```

Use a dumper build that matches the target process architecture.

## Other real-world tests

`NativePeRealWorldRunner.exe` also supports tests using `NativePeRealWorldFixture.dll`.

### Loader

```text
bin\Win64\Release\RealWorld\NativePeRealWorldRunner.exe loader bin\Win64\Release\RealWorld\NativePeRealWorldFixture.dll
```

This compares the manually loaded fixture with the Windows loader behavior.

### Exceptions

```text
bin\Win64\Release\RealWorld\NativePeRealWorldRunner.exe exceptions bin\Win64\Release\RealWorld\NativePeRealWorldFixture.dll
```

This checks exception handling in the manually loaded image.

### Recycler

```text
bin\Win64\Release\RealWorld\NativePeRealWorldRunner.exe recycler bin\Win64\Release\RealWorld\NativePeRealWorldFixture.dll
```

This checks a PE roundtrip after data was placed in a usable cave.

Use the matching Win32 runner and fixture for 32-bit tests.
