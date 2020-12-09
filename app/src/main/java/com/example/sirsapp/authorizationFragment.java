package com.example.sirsapp;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Toast;

import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.sirsapp.ui.Authorization.AuthorizationAdapter;
import com.example.sirsapp.ui.Authorization.AuthorizationDialog;
import com.example.sirsapp.ui.Authorization.AuthorizationItem;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.HybridBinarizer;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * A simple {@link Fragment} subclass.
 */
public class authorizationFragment extends Fragment {

    private static final String IMAGE_FILE_NAME = "qr.png";
    private RecyclerView recyclerView;
    private RecyclerView.LayoutManager layoutManager;
    public static List<AuthorizationItem> list = new ArrayList<>();
    public static final Object lock = new Object();
    private AuthorizationAdapter recyclerAdapter;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment

        View view = inflater.inflate(R.layout.fragment_authorization, container, false);

        // setting up the recycler view with layout manager
        this.recyclerView = view.findViewById(R.id.authorizationRecyclerView);
        this.recyclerView.setHasFixedSize(true);
        this.layoutManager = new LinearLayoutManager(getActivity());
        this.recyclerView.setLayoutManager(this.layoutManager);

        this.updateView();

        //setting up the interface clickables
        setupOnClickButtons(view);

        return view;
    }

    public void updateView() {
        // sending the list to the adapter
        this.recyclerAdapter = new AuthorizationAdapter(getActivity(), list);
        recyclerView.setAdapter(this.recyclerAdapter);
    }

    private void setupOnClickButtons(View view) {
        // setting up the buttons for the interface
        this.recyclerAdapter.setOnItemClickListener(new AuthorizationAdapter.OnItemClickListener() {
            @Override
            public void onItemClick(int position) {
                showPosition(position);
            }

            @Override
            public void onItemAccept(int position) {
                acceptButtonPressed(position);
            }

            @Override
            public void onItemDeny(int position) {
                declineButtonPressed(position);
            }
        });

        FloatingActionButton fab = view.findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                try {
                    String text = readQRcode();
                    showQRcodeDialog(text);
                } catch (Exception e) {}
            }
        });
    }

    private void showQRcodeDialog(String text) {
        // show confirmation dialog for acceptance of item
        String dialogText = "Are you sure you want to ACCEPT the item:\n" + text + "\n";
        AuthorizationDialog dialog = new AuthorizationDialog(-1, "Confirmation", dialogText, AuthorizationDialog.ACCEPT, new AuthorizationDialog.DialogConfirmation() {
            @Override
            public void onAccept(int position) {
                try {
                    new Thread(() -> {
                        acceptAuthorizationQRcode(text);
                    }).start();
                } catch (Exception e) {}
            }
        });
        dialog.show(getParentFragmentManager(), "item dialog");
    }

    private String readQRcode() throws IOException {

        Bitmap bMap = getImage();

        int width = bMap.getWidth();
        int height = bMap.getHeight();
        int[] pixels = new int[width * height];
        bMap.getPixels(pixels, 0, width, 0, 0, width, height);

        RGBLuminanceSource source = new RGBLuminanceSource(width, height, pixels);

        BinaryBitmap binaryBitmap = new BinaryBitmap(new HybridBinarizer(source));

        MultiFormatReader reader = new MultiFormatReader();
        Result result = null;
        try {
            result = reader.decode(binaryBitmap);
        } catch (NotFoundException e) {
            e.printStackTrace();
        }
        String text = result.getText();
        return text;
    }

    private Bitmap getImage() throws IOException {
        File file = new File(getContext().getFilesDir(), IMAGE_FILE_NAME);
        BufferedInputStream buf =  new BufferedInputStream(new FileInputStream(file));
        byte[] bMapArray= new byte[buf.available()];
        buf.read(bMapArray);
        return BitmapFactory.decodeByteArray(bMapArray, 0, bMapArray.length);
    }

    private void showPosition(int position){
        // shows the hash for a position
        AuthorizationItem item = list.get(position);
        AuthorizationDialog dialog = new AuthorizationDialog(position, "Confirmation ID", item.getHash() + "\n" + item.getDate());
        dialog.show(getParentFragmentManager(), "item dialog");
    }

    private void acceptButtonPressed(int position){
        // show confirmation dialog for acceptance of item
        AuthorizationItem item = list.get(position);
        String text = "Are you sure you want to ACCEPT the item:\n" + item.getHash() + "\n" + item.getDate();
        AuthorizationDialog dialog = new AuthorizationDialog(position, "Confirmation", text, AuthorizationDialog.ACCEPT, new AuthorizationDialog.DialogConfirmation() {
            @Override
            public void onAccept(int position) {
                new Thread(() -> {
                    acceptAuthorization(position);
                }).start();
            }
        });
        dialog.show(getParentFragmentManager(), "item dialog");
    }

    private void declineButtonPressed(int position){
        // show confirmation dialog for decline of item
        AuthorizationItem item = list.get(position);
        String text = "Are you sure you want to DECLINE the item:\n" + item.getHash() + "\n" + item.getDate();
        AuthorizationDialog dialog = new AuthorizationDialog(position, "Confirmation", text, AuthorizationDialog.DECLINE, new AuthorizationDialog.DialogConfirmation() {
            @Override
            public void onAccept(int position) {
                new Thread(() -> {
                    declineAuthorization(position);
                }).start();
            }
        });
        dialog.show(getParentFragmentManager(), "item dialog");
    }

    public void acceptAuthorization(int position) {
        // accept authorization confirmed
        synchronized (lock) {
            AuthorizationItem item = list.get(position);
            if (((DrawerActivity) getActivity()).answerAuthRequest(item.getHash(), true, position)) {
                getActivity().runOnUiThread(() -> {
                    recyclerAdapter.notifyItemRemoved(position);
                    updateView();
                });
            } else {
                getActivity().runOnUiThread(() -> {
                    Toast.makeText(getContext(), "An error occured, please try again later!", Toast.LENGTH_LONG).show();
                });
            }
        }
    }

    public void acceptAuthorizationQRcode(String content) {
        String hash = Base64.getEncoder().encodeToString(Cryptography.digest(content.getBytes()));
        synchronized (lock) {
            if (((DrawerActivity) getActivity()).answerAuthRequest(hash, true, -1)) {
                int position = getHashPosition(hash);
                if (position != -1) {
                    list.remove(position);
                    getActivity().runOnUiThread(() -> {
                        recyclerAdapter.notifyItemRemoved(position);
                        updateView();
                    });
                }
            } else {
                getActivity().runOnUiThread(() -> {
                    Toast.makeText(getContext(), "An error occured, please try again later!", Toast.LENGTH_LONG).show();
                });
            }
        }
    }

    private int getHashPosition(String hash){
        for (int i = 0; i < list.size(); i++){
            if (list.get(i).getHash().equals(hash)){
                return i;
            }
        }
        return -1;
    }

    public void declineAuthorization(int position) {
        // decline authorization confirmed
        synchronized (lock) {
            AuthorizationItem item = list.get(position);
            if(((DrawerActivity) getActivity()).answerAuthRequest(item.getHash(), false, position)) {
                getActivity().runOnUiThread(() -> {
                    recyclerAdapter.notifyItemRemoved(position);
                    updateView();
                });
            }

        }
    }
}