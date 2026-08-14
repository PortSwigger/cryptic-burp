plugins {
    java
}

group = "com.crypticburp"
version = "1.1"

repositories {
    mavenCentral()
}

dependencies {
    // Provided by Burp at runtime, so compileOnly.
    // All runtime crypto uses the JDK (javax.crypto),
    // so there are no third-party runtime dependencies to bundle.
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    // Burp bundles a modern JRE (21+). Target 17 bytecode for broad
    // compatibility; compiled with whatever JDK (>=17) is on the machine.
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
    options.encoding = "UTF-8"
}

tasks.test {
    useJUnitPlatform()
}

tasks.jar {
    archiveBaseName.set("crypticburp")
    manifest {
        attributes(
            "Implementation-Title" to "CrypticBurp",
            "Implementation-Version" to project.version
        )
    }
}
