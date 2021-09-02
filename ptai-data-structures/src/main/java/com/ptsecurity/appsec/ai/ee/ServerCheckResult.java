package com.ptsecurity.appsec.ai.ee;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.util.ArrayList;

@Getter
@Setter
@NoArgsConstructor
@Accessors(chain = true)
public class ServerCheckResult extends ArrayList<String> {
    public enum State {
        OK, WARNING, ERROR
    }

    @NonNull
    protected State state = State.ERROR;

    public String text() {
        return String.join(". ", this);
    }

}

