#include "pch.h"

#include <cstdint>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "output.h"

static void FreeOutput(Output* output) {
	if (!output) {
		return;
	}
	free(output->data);
	output->data = NULL;
	free(output);
}

Output* NewOutput(int bufferSize, goCallback callback)
{
	if (bufferSize <= 0) {
		bufferSize = 128;
	}

	Output* output = (Output*)malloc(sizeof(Output));
	if (!output) {
		return NULL;
	}

	output->len = bufferSize;
	output->data = (char*)malloc(output->len);
	if (!output->data) {
		free(output);
		return NULL;
	}
	memset(output->data, 0, output->len);
	output->callback = callback;

	return output;
}

void append(Output* output, const char* format, ...)
{
	// current output length
	int n = strlen((*output).data);

	// length of what we append
	va_list args;
	va_start(args, format);
	int l = vsnprintf(0, 0, format, args);
	va_end(args);

	// grow buffer if needed
	while ((n + l + 1) > (*output).len) {
		(*output).len = (*output).len * 2;
		(*output).data = (char*)realloc((*output).data, (*output).len);
	}

	// append to output
	va_start(args, format);
	vsnprintf((*output).data + strlen((*output).data), l + 1, format, args);
	va_end(args);
}

int success(Output* output)
{
	if (!output) {
		return 0;
	}

	if (output->callback) {
		output->callback(output->data, (int)strlen(output->data));
	}
	FreeOutput(output);
	return 0;
}

int failure(Output* output)
{
	if (output && output->callback) {
		output->callback(output->data, (int)strlen(output->data));
	}
	FreeOutput(output);
	return 1;
}
