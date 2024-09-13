# Restricted Embed Link Generator

## Overview

The **Restricted Embed Link Generator** is a Java application for creating secure embed links with a cryptographic signature using an EC private key.

## Features

- Load EC private key from PEM format
- Sign payload with ECDSA and SHA-256
- Generate URL with signature and optional filters

## Prerequisites

- Java 11 or higher
- Maven

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/AkhilaMukka28/embedlink.git
   cd embedlink
2. Build the project:
    ```bash
    mvn clean package

## Usage

Run the application:
    
   ```bash
    java -cp "target/*" com.imply.embed.RestrictedEmbedLink <privateKey> <baseURL> [--linkAccessFilter <value>] [--cubeAccessFilter <value>]
