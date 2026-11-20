package io.github.immaghzbad.aetherst.shared.data

/** Test sink only: the Android settings store and Compose log UI are not part of a transport test. */
internal object LogRepository {
    fun i(message: String, tag: String) = println("I/$tag: $message")
    fun w(message: String, tag: String) = println("W/$tag: $message")
    fun e(message: String, tag: String) = println("E/$tag: $message")
    fun d(message: String, tag: String) = println("D/$tag: $message")
}
