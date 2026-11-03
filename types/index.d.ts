declare namespace ZamazentaShield {
    type Platform = 'android' | 'ios';

    /**
     * - `exit`: the app is terminating (after opening ExitOnURL, if configured).
     * - `reported`: AppShieldDebugMode or ZamazentaShieldReportOnly is on; nothing was blocked.
     * - `mitigated`: neutralised in place (input dropped, content hidden); the app keeps running.
     */
    type Action = 'exit' | 'reported' | 'mitigated';

    interface ThreatEvent {
        code: number;
        id: string;
        description: string;
        action: Action;
        /** Indicators that triggered the detection, e.g. "file:/system/xbin/su". */
        evidence: string[];
        platform: Platform;
        /** Epoch milliseconds. */
        timestamp: number;
    }

    interface Status {
        platform: Platform;
        version: string;
        enabled: boolean;
        enforcing: boolean;
        /** Android only: whether libzshield (the native layer) is loaded. */
        native?: boolean;
        detections: ThreatEvent[];
        config: Record<string, boolean | number | string>;
    }

    interface Plugin {
        readonly THREATS: Readonly<Record<string, number>>;
        getStatus(): Promise<Status>;
        check(): Promise<ThreatEvent[]>;
        onThreat(listener: (event: ThreatEvent) => void): () => void;
    }
}

interface CordovaPlugins {
    ZamazentaShield: ZamazentaShield.Plugin;
}
