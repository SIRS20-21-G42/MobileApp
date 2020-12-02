package com.example.sirsapp.ui.Authorization;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.graphics.Color;
import android.os.Bundle;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatDialogFragment;

public class AuthorizationDialog extends AppCompatDialogFragment {

    private static final String INFORMATIONAL = "informational";
    public static final String ACCEPT = "accept";
    public static final String DECLINE = "decline";

    private final int position;
    private final String title;
    private final String text;
    private final String type;
    private final DialogConfirmation listener;

    public interface DialogConfirmation {
        // interface to act on confirmation button click
        void onAccept(int position);
    }

    public AuthorizationDialog(int position, String title, String text){
        this.position = position;
        this.title = title;
        this.text = text;
        this.type = INFORMATIONAL;
        this.listener = null;
    }

    public AuthorizationDialog(int position, String title, String text, String type, DialogConfirmation mListener){
        this.position = position;
        this.title = title;
        this.text = text;
        this.type = type;
        this.listener = mListener;
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());
        if (this.type.equals(INFORMATIONAL)) {
            // setting informational dialog
            builder.setTitle(this.title)
                    .setMessage(this.text)
                    .setPositiveButton("Ok", (dialog, which) -> {
                    });
        } else {
            // setting confirmation dialog
            builder.setTitle(this.title)
                    .setMessage(this.text)
                    .setPositiveButton("Confirm", (dialog, which) -> {
                        this.listener.onAccept(this.position);
                    })
                    .setNegativeButton("Cancel", (dialog, which) -> {
                    });
        }

        AlertDialog dialog = builder.create();

        dialog.setOnShowListener( new DialogInterface.OnShowListener() {
            @Override
            public void onShow(DialogInterface arg0) {
                // change colour of buttons
                if (type.equals(ACCEPT))
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(Color.parseColor("#00ff00"));
                else if (type.equals(DECLINE))
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(Color.parseColor("#ff0000"));
            }
        });

        return dialog;
    }
}
