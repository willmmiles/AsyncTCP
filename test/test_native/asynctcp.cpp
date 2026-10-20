// The library under test, compiled into the test program.
// Included rather than compiled on its own, so GCC no longer sees it as the main file and
// warns of its file-local member types.
#pragma GCC diagnostic ignored "-Wsubobject-linkage"
#include "AsyncTCP.cpp"
