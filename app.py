import streamlit as st
import pandas as pd

# ------------------------------------------------
# PAGE SETTINGS
# ------------------------------------------------

st.set_page_config(
    page_title="IoT Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# ------------------------------------------------
# LOAD DATASET
# ------------------------------------------------

@st.cache_data
def load_data():

    df = pd.read_csv("iot_dataset_scored.csv")

    df["Timestamp"] = pd.to_datetime(
        df["Timestamp"],
        errors="coerce"
    )

    return df


df = load_data()


# ------------------------------------------------
# SESSION VARIABLES
# ------------------------------------------------

if "isolated_devices" not in st.session_state:
    st.session_state.isolated_devices = set()

if "alerts" not in st.session_state:
    st.session_state.alerts = []


# ------------------------------------------------
# TITLE
# ------------------------------------------------

st.title("🛡️ IoT Security Monitoring Dashboard")

st.write(
    "Member 5 - Security Response and Monitoring"
)

st.write(
    "This dashboard reads the scored IoT dataset, "
    "detects ML-predicted anomalies, generates security "
    "alerts and simulates device isolation."
)


# ------------------------------------------------
# SIDEBAR
# ------------------------------------------------

st.sidebar.header("Dashboard Controls")

devices = sorted(
    df["Device"]
    .dropna()
    .astype(str)
    .unique()
)

selected_device = st.sidebar.selectbox(
    "Select Device",
    ["All Devices"] + devices
)


# ------------------------------------------------
# FILTER DATA
# ------------------------------------------------

if selected_device == "All Devices":

    view = df.copy()

else:

    view = df[
        df["Device"].astype(str)
        == selected_device
    ].copy()


# ------------------------------------------------
# BASIC COUNTS
# ------------------------------------------------

total_records = len(view)

normal_count = (
    view["Predicted_Label"] == "Normal"
).sum()

anomaly_count = (
    view["Predicted_Label"] == "Anomaly"
).sum()

device_count = view["Device"].nunique()


# ------------------------------------------------
# DASHBOARD SUMMARY
# ------------------------------------------------

st.subheader("📊 System Overview")

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.metric(
        "Total Records",
        f"{total_records:,}"
    )

with col2:

    st.metric(
        "Devices",
        device_count
    )

with col3:

    st.metric(
        "Normal Predictions",
        f"{normal_count:,}"
    )

with col4:

    st.metric(
        "Anomaly Predictions",
        f"{anomaly_count:,}"
    )


# ------------------------------------------------
# DEVICE STATUS
# ------------------------------------------------

st.subheader("📡 Device Security Status")

status_data = []

for device in devices:

    device_data = df[
        df["Device"].astype(str) == device
    ]

    anomaly_data = device_data[
        device_data["Predicted_Label"] == "Anomaly"
    ]

    if device in st.session_state.isolated_devices:

        status = "🔒 ISOLATED"

    elif len(anomaly_data) > 0:

        status = "🔴 ANOMALY DETECTED"

    else:

        status = "🟢 NORMAL"

    latest_data = device_data.sort_values(
        "Timestamp"
    ).iloc[-1]

    latest_score = latest_data["Anomaly_Score"]

    status_data.append({
        "Device": device,
        "Status": status,
        "Anomaly Records": len(anomaly_data),
        "Latest Anomaly Score": round(
            latest_score,
            3
        )
    })


status_df = pd.DataFrame(status_data)

st.dataframe(
    status_df,
    use_container_width=True,
    hide_index=True
)


# ------------------------------------------------
# SECURITY RESPONSE
# ------------------------------------------------

st.subheader("🚨 Security Response")


anomalies = view[
    view["Predicted_Label"] == "Anomaly"
].copy()


if len(anomalies) == 0:

    st.success(
        "No anomaly detected for the selected device."
    )

else:

    # Select the highest anomaly score
    threat = anomalies.sort_values(
        "Anomaly_Score",
        ascending=False
    ).iloc[0]

    device = str(threat["Device"])

    attack = str(threat["Attack_Type"])

    score = float(
        threat["Anomaly_Score"]
    )

    st.warning(
        "⚠️ Suspicious activity detected!"
    )

    col1, col2 = st.columns(2)

    with col1:

        st.write(
            f"**Device:** {device}"
        )

        st.write(
            f"**Attack Type:** {attack}"
        )

        st.write(
            f"**Anomaly Score:** {score:.3f}"
        )

        st.write(
            f"**ML Prediction:** "
            f"{threat['Predicted_Label']}"
        )

    with col2:

        if device in st.session_state.isolated_devices:

            st.error(
                "🔒 DEVICE ISOLATED"
            )

            if st.button(
                "Restore Device"
            ):

                st.session_state.isolated_devices.remove(
                    device
                )

                st.rerun()

        else:

            st.error(
                "🚨 SECURITY RESPONSE REQUIRED"
            )

            if st.button(
                "🔒 Isolate Device"
            ):

                st.session_state.isolated_devices.add(
                    device
                )

                st.session_state.alerts.insert(
                    0,
                    {
                        "Device": device,
                        "Attack Type": attack,
                        "Anomaly Score": round(
                            score,
                            3
                        ),
                        "Action":
                        "DEVICE ISOLATED"
                    }
                )

                st.rerun()


# ------------------------------------------------
# SECURITY ALERT LOG
# ------------------------------------------------

st.subheader("📋 Security Alert Log")


if len(st.session_state.alerts) == 0:

    st.info(
        "No security response has been triggered yet."
    )

else:

    alerts_df = pd.DataFrame(
        st.session_state.alerts
    )

    st.dataframe(
        alerts_df,
        use_container_width=True,
        hide_index=True
    )


# ------------------------------------------------
# CHARTS
# ------------------------------------------------

st.subheader("📈 Security Analysis")


col1, col2 = st.columns(2)


with col1:

    st.write(
        "Normal vs Anomaly"
    )

    prediction_counts = (
        view["Predicted_Label"]
        .value_counts()
    )

    st.bar_chart(
        prediction_counts
    )


with col2:

    st.write(
        "Attack Types"
    )

    attack_counts = (
        view[
            view["Predicted_Label"]
            == "Anomaly"
        ]["Attack_Type"]
        .fillna("Unknown")
        .value_counts()
    )

    if len(attack_counts) > 0:

        st.bar_chart(
            attack_counts
        )

    else:

        st.info(
            "No attacks detected."
        )


# ------------------------------------------------
# ANOMALY SCORE GRAPH
# ------------------------------------------------

st.subheader(
    "📊 Anomaly Score Over Time"
)

score_data = view[
    ["Timestamp", "Anomaly_Score"]
].dropna()

score_data = score_data.sort_values(
    "Timestamp"
)

if len(score_data) > 0:

    score_data = score_data.set_index(
        "Timestamp"
    )

    st.line_chart(
        score_data["Anomaly_Score"]
    )


# ------------------------------------------------
# RECENT DATA
# ------------------------------------------------

st.subheader(
    "🔎 Dataset Records"
)

st.dataframe(
    view.sort_values(
        "Timestamp",
        ascending=False
    ).head(30),
    use_container_width=True,
    hide_index=True
)


# ------------------------------------------------
# FOOTER
# ------------------------------------------------

st.divider()

st.caption(
    "Member 5 Security Response Layer | "
    "Isolation is simulated for demonstration."
)